require 'net/ldap'

module Devise
  module LdapPassword
    def self.generate(method, password)
      case method
        when :ssha
        self.generate_ssha(password)
      else
        Net::LDAP::Password.generate(:sha, password)
      end
    end
    
    def self.generate_ssha(password, salt=nil)
      if salt and salt.size != 4
        raise ArgumentError, _("salt size must be == 4: %s") % salt.inspect
      end
      salt ||= Salt.generate(4)
      sha1_hash_with_salt = "#{Digest::SHA1.digest(password + salt)}#{salt}"
      "{SSHA}#{[sha1_hash_with_salt].pack('m').chomp}"
    end
    
    module Salt
      CHARS = ['.', '/'] + ['0'..'9', 'A'..'Z', 'a'..'z'].collect do |x|
        x.to_a
      end.flatten

      def self.generate(length)
        salt = ""
        length.times {salt << CHARS[rand(CHARS.length)]}
        salt
      end
    end
    
  end
end