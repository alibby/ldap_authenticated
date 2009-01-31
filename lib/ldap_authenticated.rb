
# When we started using jruby ldap, we discovered that it does
# not have a to_hash method on the entry like ruby ldap does.
# so we patch it in here.

if RUBY_PLATFORM =~ /^java.*/i
  class LDAP::Entry
     def to_hash
        h = {}
        get_attributes.each { |a| h[a.downcase.to_sym] = self[a] }
        h[:dn] = [dn]
        h
     end
  end
end

module LdapAuthenticated
  module ActMethods
    def ldap_authenticated(options = {})
      
      class_inheritable_accessor :config
      class_inheritable_accessor :bootstrap_action
      class_inheritable_accessor :login_requires
      
      self.config = options[:config] || self
      self.bootstrap_action = options[:bootstrap_action] || proc { true }
      self.login_requires = options[:login_requires] || prox {}
      
      unless included_modules.include?(InstanceMethods)
        extend ClassMethods
        include InstanceMethods
      end
    end    
  end
  
  module ClassMethods
    
    def call_thing(thing,*params)
      puts "Trying to call #{thing} with #{params}"
      if thing.class == Symbol
        self.send(thing,*params)
      elsif thing.class == Prox
        thing.call(*params)
      else
        puts "I don't know how to call a #{thing.class}"
      end
    end
    
    # Authenticate a user with username and password.
    def authenticate(username, password)
      username = username.downcase
      user = fetch_ldap_user_entry(username)
      
      return nil unless user      
      return nil unless call_thing(login_requires, user)
      
      with_ldap do |conn|
        begin
          conn.bind(user.dn.first, password)
        rescue LDAP::ResultError => e
          raise e unless e.message == 'Invalid credentials'
          return nil
        end
        
        u = find_in_state :first, :active, :conditions => ["login = ?", username] #{:login => username}
        u = call_thing(bootstrap_action, user, password) if( config.ldap_account_bootstrapping && u.nil? )        
        u
      end
    rescue LDAP::ResultError => e
      puts "LDAP ERROR: #{e}"
      nil
    end
        
    def with_ldap
      conn = LDAP::Conn.new(config.ldap_server, config.ldap_port)
      conn.set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, 3)
      yield conn
    end
    
    def fetch_ldap_user_entry(username)
      with_ldap do |conn|
        begin 
          conn.bind(config.ldap_binddn, config.ldap_bindpw)
          filter = "(#{config.ldap_user_key||'uid'}=#{username})"
          user = nil
          conn.search(config.ldap_basedn, 2, filter) { |entry|
            user = entry ? OpenStruct.new(entry.to_hash) : nil
          }
          user
        rescue LDAP::ResultError => e
          if e.message == 'Invalid credentials'
            raise LDAP::ResultError.new("Could not bind as config.ldap_binddn user #{config.ldap_binddn} (perpahs config.yml is borked?)")
          else
            raise e
          end
        end
      end
    end
  end
  
  module InstanceMethods
    def authenticated=(status)
      @authenticated = status
    end
    
    def authenticated?
      @authenticated
    end    
  end
end
