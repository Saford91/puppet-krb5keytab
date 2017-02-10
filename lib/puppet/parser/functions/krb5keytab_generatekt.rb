#   Copyright 2014 Collective, Inc.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# -------------------------------------------------------
#
# This function creates a kerberos host principal if necessary and then returns a keytab

module Puppet::Parser::Functions
  require 'tempfile'
  newfunction(:krb5keytab_generatekt, :type => :rvalue) do |args_in|

    # Validate arguments
    args = args_in[0]
    fail "Usage: krb5keytab_generatekt(options_hash) -- #{args.inspect}" if ! args.is_a?(Hash)
    req_keys = %w{admin_keytab admin_principal realm admin_server}
    req_keys.each do |key|
      fail "Required option key #{key} was not defined" if ! args.key?(key)
    end
    
    # Build 'kadmin' object -- the class is below
    kadmin = Kadmin.new(
      args['admin_principal'],
      args['admin_keytab'],
      args['admin_server'],
      args['realm']
    )
    
    # Check to see if the principal exists now
    # Create it if it doesn't
    the_principal = nil
    if (args.key?('principal'))
      the_principal = args['principal']
      the_principal += "@#{args['realm']}" if the_principal !~ /@/
    else  
      fail "Required option 'fqdn' was not defined" if ! args.key?('fqdn')
      the_principal = "host/#{args['fqdn']}@#{args['realm']}"
    end
    princ = kadmin.getprinc(the_principal)
    if princ.nil?
      success = kadmin.createprinc(the_principal)
      fail "Unable to create #{the_principal}!" if ! success
    end
    
    # Grab the keytab
    tmpfile = Tempfile.new('host_keytab')
    path = tmpfile.path
    tmpfile.close
    tmpfile.unlink
    begin
      success = kadmin.addkeytab(the_principal, path)
      fail "Unable to create #{path} with key for #{the_principal}!" if ! success
      f = File.open(path, "rb")
      f.binmode
      content = f.read
      f.close
    ensure
      File.unlink(path) if File.file?(path)
    end
    
    # Done!
    return content
    
  end

  # A class to help interact with the 'kadmin' command line tool
   
  class Kadmin
    require 'shellwords'
    require 'tempfile'
    require 'base64'
    def initialize(principal, keytab, admin_server, realm)
      @principal = principal
      kt = File.open(keytab, "r")
      kt.binmode
      @keytab = kt.read
      kt.close
      File.unlink(keytab)
      @admin_server = admin_server
      @realm = realm
    end
    
    def addkeytab(princ, path)
      cmd="ktadd -k \"#{path}\" \"#{princ}\""
      output = run_kadmin(cmd)
      return false if ! File.file?(path)
      output.each do |line|
        return true if line =~ /^Entry for principal \S+ with kvno \d+/
      end
      return false
    end
  
    def getprinc (princ)
      data = nil
      fields = %w{
        princ-canonical-name
        princ-exp-time
        last-pw-change
        pw-exp-time
        princ-max-life
        modifying-princ-canonical-name
        princ-mod-date
        princ-attributes
        princ-kvno
        princ-mkvno
        princ-policy
        princ-max-renewable-life
        princ-last-success
        princ-last-failed
        princ-fail-auth-count
        princ-n-key-data
        ver
        kvno
      }
      output = run_kadmin("getprinc -terse #{princ}")
      output.each do |line|
        x = line.split(/\t/)
        data = Hash.new
        fields.each do |field|
          data[field] = x.shift
          data[field] = $1 if data[field] =~ /^"(.*)"$/
        end
      end
      data
    end
  
    def createprinc (princ)
      host_princ_cmd = "addprinc -randkey"
      host_princ_cmd.concat(" #{princ}")
      output = run_kadmin(host_princ_cmd)
      return false if output.empty?
      return false if output[0] !~ /^Principal "[^"]+" created/
      return true
    end
  
    private
    def run_kadmin (command)
      keytab_tmpfile = Tempfile.new('keytab')
      keytab_tmpfile.binmode
      keytab_tmpfile.write(@keytab)
      keytab_tmpfile.close
      cmd = "kadmin -p #{@principal.shellescape} -k -t #{keytab_tmpfile.path} -s #{@admin_server} -q #{command.shellescape} -r #{@realm.shellescape}"
      begin
        output = `#{cmd}`
      ensure
        keytab_tmpfile.unlink
      end
      result = Array.new
      output.split(/\n/).each do |line|
        next if line =~ /^Authenticating as principal /
        result << line.chomp
      end
      result      
    end
  end
end
