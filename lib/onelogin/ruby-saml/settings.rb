module Onelogin
  module Saml
    class Settings
      attr_accessor :assertion_consumer_service_url, :issuer, :sp_name_qualifier
      attr_accessor :idp_sso_target_url, :idp_cert_fingerprint, :idp_cert, :name_identifier_format
      attr_accessor :authn_context
      attr_accessor :private_key
      attr_accessor :force_auth
    end
  end
end
