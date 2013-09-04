# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the License). You may not use this file except in
# compliance with the License.
#
# You can obtain a copy of the License at
# https://opensso.dev.java.net/public/CDDLv1.0.html or
# opensso/legal/CDDLv1.0.txt
# See the License for the specific language governing
# permission and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# Header Notice in each file and include the License file
# at opensso/legal/CDDLv1.0.txt.
# If applicable, add the following below the CDDL Header,
# with the fields enclosed by brackets [] replaced by
# your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
#
# $Id: xml_sec.rb,v 1.6 2007/10/24 00:28:41 todddd Exp $
#
# Copyright 2007 Sun Microsystems Inc. All Rights Reserved
# Portions Copyrighted 2007 Todd W Saxton.

require 'rubygems'
require "rexml/document"
require "rexml/xpath"
require "openssl"
require "xmlcanonicalizer"
require "digest/sha1"
require "digest/sha2"
require "onelogin/ruby-saml/validation_error"
require 'rsa_ext'

module XMLSecurity

  class SignedDocument < REXML::Document
    DSIG = "http://www.w3.org/2000/09/xmldsig#"

    attr_accessor :signed_element_id

    def initialize(response)
      super(response)
      extract_signed_element_id
    end

    def validate(idp_cert_fingerprint, soft = true)
      # get cert from response
      base64_cert = REXML::XPath.first(self, "//ds:X509Certificate").text
      cert_text   = Base64.decode64(base64_cert)
      cert        = OpenSSL::X509::Certificate.new(cert_text)

      # check cert matches registered idp cert
      fingerprint = Digest::SHA1.hexdigest(cert.to_der)

      if fingerprint != idp_cert_fingerprint.gsub(/[^a-zA-Z0-9]/,"").downcase
        return soft ? false : (raise Onelogin::Saml::ValidationError.new("Fingerprint mismatch"))
      end

      validate_doc(base64_cert, soft)
    end

    def validate_doc(base64_cert, soft = true)
      # validate references

      # check for inclusive namespaces

      inclusive_namespaces            = []
      inclusive_namespace_element     = REXML::XPath.first(self, "//ec:InclusiveNamespaces")

      if inclusive_namespace_element
        prefix_list                   = inclusive_namespace_element.attributes.get_attribute('PrefixList').value
        inclusive_namespaces          = prefix_list.split(" ")
      end

      # remove signature node
      sig_element = REXML::XPath.first(self, "//ds:Signature", {"ds"=>DSIG})
      sig_element.remove

      # check digests
      REXML::XPath.each(sig_element, "//ds:Reference", {"ds"=>DSIG}) do |ref|
        uri                           = ref.attributes.get_attribute("URI").value
        hashed_element                = REXML::XPath.first(self, "//[@ID='#{uri[1..-1]}']")
        canoner                       = XML::Util::XmlCanonicalizer.new(false, true)
        canoner.inclusive_namespaces  = inclusive_namespaces if canoner.respond_to?(:inclusive_namespaces) && !inclusive_namespaces.empty?
        canon_hashed_element          = canoner.canonicalize(hashed_element).gsub('&','&amp;')
        algorithm                     = digest_algorithm(REXML::XPath.first(ref, "//ds:DigestMethod"))
        hash                          = Base64.encode64(algorithm.digest(canon_hashed_element)).chomp
        digest_value                  = REXML::XPath.first(ref, "//ds:DigestValue", {"ds"=>DSIG}).text

        unless digests_match?(hash, digest_value)
          return soft ? false : (raise Onelogin::Saml::ValidationError.new("Digest mismatch"))
        end
      end

      # verify signature
      canoner                 = XML::Util::XmlCanonicalizer.new(false, true)
      signed_info_element     = REXML::XPath.first(sig_element, "//ds:SignedInfo", {"ds"=>DSIG})
      canon_string            = canoner.canonicalize(signed_info_element)

      base64_signature        = REXML::XPath.first(sig_element, "//ds:SignatureValue", {"ds"=>DSIG}).text
      signature               = Base64.decode64(base64_signature)

      # get certificate object
      cert_text               = Base64.decode64(base64_cert)
      cert                    = OpenSSL::X509::Certificate.new(cert_text)

      # signature method
      algorithm               = signature_algorithm(REXML::XPath.first(signed_info_element, "//ds:SignatureMethod"))

      if !cert.public_key.verify(algorithm.new, signature, canon_string)
        return soft ? false : (raise ValidationError.new("Key validation error"))
      end

      return true
    end
    
    def decode private_key
      
      pk_raw = File.read private_key
      private_key = OpenSSL::PKey::RSA.new(pk_raw)
      
      # This is the public key which encrypted the first CipherValue
      cert1, cert = REXML::XPath.match(self, '//ds:X509Certificate', 'ds' => "http://www.w3.org/2000/09/xmldsig#")
      
      c1, c2 = REXML::XPath.match(self, '//xenc:CipherValue', 'xenc' => 'http://www.w3.org/2001/04/xmlenc#')
      
      cert = cert || cert1

      cert = OpenSSL::X509::Certificate.new(Base64.decode64(cert.text))
      return false unless cert.check_private_key(private_key)

      # Generate the key used for the cipher below via the RSA::OAEP algo
      rsak = RSA::Key.new private_key.n, private_key.d
      v1s  = Base64.decode64(c1.text)

      begin
        cipherkey = RSA::OAEP.decode rsak, v1s
      rescue RSA::OAEP::DecodeError
        return false
      end

      # The aes-128-cbc cipher has a 128 bit initialization vector (16 bytes)
      # and this is the first 16 bytes of the raw string.
      bytes  = Base64.decode64(c2.text).bytes.to_a
      iv     = bytes[0...16].pack('c*')
      others = bytes[16..-1].pack('c*')

      cipher = OpenSSL::Cipher.new('aes-128-cbc')
      cipher.decrypt
      cipher.iv  = iv
      cipher.key = cipherkey

      out = cipher.update(others)

      # The encrypted string's length might not be a multiple of the block
      # length of aes-128-cbc (16), so add in another block and then trim
      # off the padding. More info about padding is available at
      # http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html in
      # Section 5.2
      out << cipher.update("\x00" * 16)
      padding = out.bytes.to_a.last
      self.class.new(out[0..-(padding + 1)])
    end

    private

    def digests_match?(hash, digest_value)
      hash == digest_value
    end

    def extract_signed_element_id
      reference_element       = REXML::XPath.first(self, "//ds:Signature/ds:SignedInfo/ds:Reference", {"ds"=>DSIG})
      self.signed_element_id  = reference_element.attribute("URI").value[1..-1] unless reference_element.nil?
    end

    def digest_algorithm(element)
      algorithm = element.attribute("Algorithm").value if element
      algorithm && algorithm =~ /sha(256|384|512)$/ ? Digest::SHA2 : Digest::SHA1
    end

    def signature_algorithm(element)
      algorithm = element.attribute("Algorithm").value if element
      if algorithm
        algorithm =~ /sha(.*?)$/i
        algorithm = $1.to_i
      end
      case algorithm
      when 256 then OpenSSL::Digest::SHA256
      when 384 then OpenSSL::Digest::SHA384
      when 512 then OpenSSL::Digest::SHA512
      else
        OpenSSL::Digest::SHA1
      end
    end

  end
end
