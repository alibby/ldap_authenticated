
require 'rubygems'
require 'ldap'
ActiveRecord::Base.send(:extend, LdapAuthenticated::ActMethods)
