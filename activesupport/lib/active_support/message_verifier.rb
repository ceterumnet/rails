# Fork of MessageVerifier from Rails 3.2.3
# https://raw.github.com/rails/rails/f3e1b21ca91afbd97f33d1e51808dd320d82b4de/activesupport/lib/active_support/message_verifier.rb
# Author: Jeff Yip (jeffyip)
# This should work with Rails 3.0 - Rails 3.2

require 'active_support/base64'
require 'active_support/deprecation'
require 'active_support/core_ext/object/blank'

module ActiveSupport
  # +MessageVerifier+ makes it easy to generate and verify messages which are signed
  # to prevent tampering.
  #
  # This is useful for cases like remember-me tokens and auto-unsubscribe links where the
  # session store isn't suitable or available.
  #
  # Remember Me:
  #   cookies[:remember_me] = @verifier.generate([@user.id, 2.weeks.from_now])
  #
  # In the authentication filter:
  #
  #   id, time = @verifier.verify(cookies[:remember_me])
  #   if time < Time.now
  #     self.current_user = User.find(id)
  #   end
  #
  # By default it uses Marshal to serialize the message. If you want to use another
  # serialization method, you can set the serializer attribute to something that responds
  # to dump and load, e.g.:
  #
  #   @verifier.serializer = YAML
  class MessageVerifier
    class InvalidSignature < StandardError; end

    def initialize(secret, options = {})
      unless options.is_a?(Hash)
        ActiveSupport::Deprecation.warn "The second parameter should be an options hash. Use :digest => 'algorithm' to specify the digest algorithm."
        options = { :digest => options }
      end

      @secret = secret
      @digest = options[:digest] || 'SHA1'
      @serializer = options[:serializer] || Marshal
    end

    def verify(signed_message)
      raise InvalidSignature if signed_message.blank?

      data, digest = signed_message.split("--")
      if data.present? && digest.present? && secure_compare(digest, generate_digest(data))

        begin
          # Temporary hack to support multiple serializers
          if data.start_with?('BA')
            ::Marshal.load(::Base64.decode64(data))
          elsif data.start_with?('ey')
            ::JSON.load(::Base64.decode64(data))
          else
            @serializer.load(::Base64.decode64(data))
          end
        rescue StandardError
          {}
        end

      else
        raise InvalidSignature
      end
    end

    def generate(value)
      data = ::Base64.strict_encode64(@serializer.dump(value))
      "#{data}--#{generate_digest(data)}"
    end

    private
      # constant-time comparison algorithm to prevent timing attacks
      def secure_compare(a, b)
        return false unless a.bytesize == b.bytesize

        l = a.unpack "C#{a.bytesize}"

        res = 0
        b.each_byte { |byte| res |= byte ^ l.shift }
        res == 0
      end

      def generate_digest(data)
        require 'openssl' unless defined?(OpenSSL)
        OpenSSL::HMAC.hexdigest(OpenSSL::Digest.const_get(@digest).new, @secret, data)
      end
  end
end
