#!/usr/bin/env ruby

require 'base64'
require 'cgi'
require 'securerandom'
require 'time'
require 'zlib'

# utils ------------------------------------------------------------------------

def h(msg, char)
  puts ''
  puts msg.upcase
  puts char * msg.size
end

define_method(:h1) { |msg| h(msg, '=') }
define_method(:h2) { |msg| h(msg, '-') }

def deflate(inflated)
  Zlib::Deflate.deflate(inflated, 9)[2..-5]
end

def inflate(deflated)
  zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
  buf = zstream.inflate(deflated)
  zstream.finish
  zstream.close
  buf
end

def eql(a, b)
  return false if a.size != b.size
  i = 0
  while i <= a.size
    if a[i] != b[i]
      puts "...#{a[[i-10, 0].max..[i+10, a.size-1].min]}..."
      puts "#{'-' * 13}^"
      puts "#{a[i]} != #{b[i]} @ #{i}"
      puts "#{a[i].ord} != #{b[i].ord} @ #{i}"
      return false
    end
    i += 1
  end
  true
end

def compact_xml(xml)
  xml.gsub(/^\s+/, '').gsub(/>\n/, '>').gsub(/\n+/, ' ').strip
end

# work -------------------------------------------------------------------------

ASSERTION_CONSUMER_SERVICE_URL = 'https://resource.example.com/saml/consume'
SSO_DESTINATION = 'https://auth.example.com/saml/sso/trust'

# HARDCODED FOR DEMONSTRATION, DO NOT USE THESE!!!!
CERT = <<-CERT
-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIICgZNt31bqJIwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVbWluaWNhIHJvb3QgY2EgMzQwNzIwMCAXDTE4MTAxMzA5MjYzOVoYDzIxMDgx
MDEzMTAyNjM5WjAbMRkwFwYDVQQDExBhdXRoLmV4YW1wbGUuY29tMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtWINs0jqRjRjgaxaKRLa5XoY+XWVA8a8
n0KOxsVVtZ2nfDn90kIwnzK/IRy8azhtKTBcM+6IRK1QHm3xY8z+1qciaMOe4IEx
S/6R7qixoLLrTqAuDks8nNwe9rdsfnitAPwuHvblQBf5InIoDkd/B6zSl82nOneZ
mIJYD8ZwxE5mb28IkgrzrBnmndrr7MoTaL2tSYkOez0JAIpFoDrUgxYa9FDO3zPi
0VfVT3d8p3oFidKo0/mdBS5zpfwAHwqaV1lpLivcLot6UJzMxsRYGW90kqdxU2oP
lDecGfTROcO8RA0GNStu/LhKlgl+fxGhxFpZpXbXyGWXFavsNCtVJwIDAQABo1ww
WjAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MAwGA1UdEwEB/wQCMAAwGwYDVR0RBBQwEoIQYXV0aC5leGFtcGxlLmNvbTANBgkq
hkiG9w0BAQsFAAOCAQEAUvmywzSyMXsUZTpbnMR7S2s0NgAosfCqh3hcYNYxRUii
HpAROaE7dPbG3+xKfOwmMkPmJSqJyUtaAlKdLOXHjWD/Bzip4Ji7q9DmniSSqiRU
fmESIAE574Qcx51yL6hyswbj1clvlX7Cf87prMKitJj+FjqJYM041RXEDKEOH4LK
Bt5y13VepcUDzRJktmOuEDMGE1750E/tL/WX+ABw5TcGte7qQFI/nRSHoZl8fmQ6
+NhdIOvIwySnq8ouwI4vKeKTHPs3jlJ7g4g6yT8IsZJ7C+Qj/PXEl7Lbz36HkclP
Vt6cYjiri6H6yqJsVEyBvxRPJULTGr3E3scwdhZB1Q==
-----END CERTIFICATE-----
CERT
PRIVATE_KEY = <<-PK
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtWINs0jqRjRjgaxaKRLa5XoY+XWVA8a8n0KOxsVVtZ2nfDn9
0kIwnzK/IRy8azhtKTBcM+6IRK1QHm3xY8z+1qciaMOe4IExS/6R7qixoLLrTqAu
Dks8nNwe9rdsfnitAPwuHvblQBf5InIoDkd/B6zSl82nOneZmIJYD8ZwxE5mb28I
kgrzrBnmndrr7MoTaL2tSYkOez0JAIpFoDrUgxYa9FDO3zPi0VfVT3d8p3oFidKo
0/mdBS5zpfwAHwqaV1lpLivcLot6UJzMxsRYGW90kqdxU2oPlDecGfTROcO8RA0G
NStu/LhKlgl+fxGhxFpZpXbXyGWXFavsNCtVJwIDAQABAoIBAGVzYpZUwjRiOQXe
kM9IbIbNtApTafWiwv2RDKrA1R+v/m3NQdrIismAaMbse7a86NGQ6wFg+XbwOU/L
zqgzkJYfBW/zenm3yQroaFdEo5VufY6MqTX1fwF9XRRBo71ZYeqbInDPR4qB3icW
ErFp6/MvBttBe7eIDbDvtrGcHJavEi6gXRZbrsRbdilVUDrE4793qQBOYqn8AHh/
wyDPJN0tWEOYY0Mg4Vq4SxDvoS+B1uFFd58xO8af7moP0BHpZ1cGcoPzXXuIaogq
OrGKaYFpRD8tfV7zKQM0akx84pQpggYHOVhH2zhruoW3/fjlTstX3wwDrcwyUhdC
T95NWIECgYEA1y9RWEZl+QcgUXQICcOh/3pKPfdjy+tZYu6WyPThk1U2wK6elKYT
8T8fPn0KquHtxtvX5/zwvDkU4Eu/2C3pcKIA239DiYoyLjSVkakFkvOA83qRwdmN
KmktwrnpSJu5veMmGpumGT3NaOlBpw8Xq24uCwUV3sokR7i6Hi1nVuMCgYEA18lt
ub8fv08ym/I1QtERhDOKDyrfZpidSkyAiRGTi0ogrvc/wZLTCLt/gTD+2dK2U6pR
SnkcIf/dwjbTRYqYqW0QhnWLAjIbktZ94WrPrXz1gSWX43Xyva3LSpAnz5DhgACE
JSZrKbe3ru8jOGxEGt8fKSp47bVJeqbjAU/Al+0CgYBP4PjJVBi2gLa2heQV+9E/
DR5SMmuRXyQnXXoLzxuNnaxdinTDqYLtowjuIWy8UnH5x9I2A+c5d9cQDA6DKUfm
z7yRvoRLoklObaa4E45GJq5Ps8g3tZJ5k+Gwz2KR2XzxyEh0yCK4bAC8WRpN8YRP
1u6wmIqt0Uv2c9RjL2eVEQKBgQCvjEsbxYTKWl/NxmnWBce+ST+Tv0knahjsDPi0
ifwCYTfdn3/attvASukb7QQnqOhzgCfJ8mUUs9dw3LFb7bjsfLHo8U85ZhJQjvax
n/d8KCCCBFdg0N+9t9meu0/n6PHK9KCMqIid07w3MIzypgFx6vqqvsbKe6Vfhs0+
j+casQKBgQDVVQpEHhBkNqJSnrD8KqkAqBhzCyh2/k2zatI4W+hjoVmM8AQcye8e
w2CArwIZ/xboksnUCuS9nd8tzfvTRiqadin/Ucxg6W1GuAWsAksV/+KXak++sMqJ
H71hQw80ELH23Z7jIUUR5Tpro60gDzYx0epITEpuZ3kiQqh6VFVuIQ==
-----END RSA PRIVATE KEY-----
PK

def authn_request
  compact_xml %{
    <samlp:AuthnRequest
      AssertionConsumerServiceURL="#{ASSERTION_CONSUMER_SERVICE_URL}"
      Destination="#{SSO_DESTINATION}"
      ID="#{SecureRandom.uuid}"
      IssueInstant="#{Time.now.utc.iso8601}"
      Version="2.0"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
      <saml:Issuer>http://https://example.com/saml/metadata</saml:Issuer>
      <samlp:NameIDPolicy
        AllowCreate="true"
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" />
      <samlp:RequestedAuthnContext Comparison="exact">
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </samlp:RequestedAuthnContext>
    </samlp:AuthnRequest>}
end

def authn_redirect_url(request)
  deflated = deflate(request)
  "#{SSO_DESTINATION}?SAMLRequest=#{CGI.escape(Base64.strict_encode64(deflated))}"
end

def parse_authn_request(url)
  params = CGI::parse(url.split('?', 2)[1])
  inflate(Base64.decode64(params['SAMLRequest'][0]))
end

class Response
  def initialize(request)
    @request = request
    @email = 'bob@stdin.co'
    @request_id = request[/ID=['"](.+?)['"]/, 1]
    @acs_url = request[/AssertionConsumerServiceURL=['"](.+?)['"]/, 1]
    @response_id = SecureRandom.uuid
    @reference_id = SecureRandom.uuid
    @audience_uri = @acs_url[/^(.*?\/\/.*?\/)/, 1]
    @issuer_uri = 'https://auth.example.com'
    @now = Time.now.utc
    @ttl = 60
  end

  def assertion
    compact_xml %{
      <saml:Assertion
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="_#{@reference_id}"
        IssueInstant="#{@now.iso8601}"
        Version="2.0">
        <saml:Issuer Format="urn:oasis:names:SAML:2.0:nameid-format:entity">#{@issuer_uri}</saml:Issuer>
        <saml:Subject>
          <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">#{@email}</saml:NameID>
          <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData
              #{@request_id ? %[InResponseTo="#{@request_id}"] : ""}
              NotOnOrAfter="#{(@now+3*60).iso8601}"
              Recipient="#{@acs_url}" />
          </saml:SubjectConfirmation>
        </saml:Subject>

        <saml:Conditions
          NotBefore="#{(@now-5).iso8601}"
          NotOnOrAfter="#{(@now+60*60).iso8601}">
          <saml:AudienceRestriction>
            <saml:Audience>#{@audience_uri}</saml:Audience>
          </saml:AudienceRestriction>
        </saml:Conditions>

        <saml:AttributeStatement>
          <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">
            <saml:AttributeValue>#{@email}</saml:AttributeValue>
          </saml:Attribute>
        </saml:AttributeStatement>

        <saml:AuthnStatement
          AuthnInstant="#{@now.iso8601}"
          SessionIndex="_#{@reference_id}"
          #{@ttl > 0 ? %{SessionNotOnOrAfter="#{(@now + @ttl).iso8601}"} : ''}>
          <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:federation:authentication:windows</saml:AuthnContextClassRef>
          </saml:AuthnContext>
        </saml:AuthnStatement>
      </saml:Assertion>
    }
  end

  def signed_info
    digest = Base64.encode64(
      OpenSSL::Digest::SHA512.digest(assertion)
    ).gsub(/\n/, '')
    compact_xml %[
      <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
        <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha512" />
        <ds:Reference URI="#_#{@reference_id}">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha512" />
          <ds:DigestValue>#{digest}</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>]
  end

  def signature
    key = OpenSSL::PKey::RSA.new(PRIVATE_KEY)
    signature_value = Base64.strict_encode64(key.sign(OpenSSL::Digest::SHA512.new, signed_info))
    compact_xml %[
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        #{signed_info}
        <ds:SignatureValue>#{signature_value}</ds:SignatureValue>
        <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
          <ds:X509Data>
            <ds:X509Certificate>#{Base64.strict_encode64(CERT)}</ds:X509Certificate>
          </ds:X509Data>
        </KeyInfo>
      </ds:Signature>]
  end


  def xml
    compact_xml %[
      <samlp:Response ID="_#{@response_id}" Version="2.0"
        IssueInstant="#{@now.iso8601}" Destination="#{@acs_url}"
        Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified"
        #{@request_id ? %[ InResponseTo="#{@saml_request_id}"] : ""}
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
        <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">#{@issuer_uri}</saml:Issuer>
        <samlp:Status>
          <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
        </samlp:Status>
        #{assertion.sub(/Issuer\>/, "Issuer>#{signature}")}
      </samlp:Response>]
  end
end

# show -------------------------------------------------------------------------

def main
  h1 'authentication request'
  req = authn_request
  puts req
  h2 'redirect url'
  url = authn_redirect_url(req)
  puts url
  parsed = parse_authn_request(url)
  raise "\n#{req} #{req.size} does not match\n#{parsed} #{parsed.size}\n#{parsed <=> req}" unless eql parsed, req
  h2 'parsed request is the same as the original request'
  res = Response.new(req)
  h2 'assertion'
  puts res.assertion
  h2 'SignedInfo'
  puts res.signed_info
  h2 'signature'
  puts res.signature
  h2 'final response'
  puts res.xml
end

if $PROGRAM_NAME == __FILE__
  main
end
