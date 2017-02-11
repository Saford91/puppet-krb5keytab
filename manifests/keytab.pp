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
# This class manages the a kerberos principal and possibly a kerberos keytab
# -----------------
# Requires stdlib

define krb5keytab::keytab (
  $admin_keytab      = hiera('krb5keytab::admin-keytab'),
  $admin_princ       = hiera('krb5keytab::admin-principal'),
  $krb5_realm        = hiera('krb5keytab::krb5-realm'),
  $krb5_admin_server = hiera('krb5keytab::krb5-admin-server'),
  $keytab            = '/etc/krb5.keytab',
  $keytab_owner      = 'root',
  $keytab_group      = 'root',
  $keytab_mode       = '0600',
) {
  
  validate_absolute_path($keytab)

  #
  # Build/obtain the keytab
  #
  
  if (has_key($::krb5principals, "${name}@${krb5_realm}")) {

    # If the keytab is already present, only ensure file permissions

    file { $keytab:
      path  => $keytab,
      owner => $keytab_owner,
      group => $keytab_group,
      mode  => $keytab_mode,
    }

  } else {

    # Store the keytab contents in a file on the server and pass in the
    # argument as a filename. Otherwise if there's an error the puppet agent might
    # be able to see the key in the error message, and that would be bad!

    $admin_keytab_file_path = krb5keytab_writefile(base64('decode',$admin_keytab))

    #
    # Get the keytab from the Kerberos server. This calls the
    # lib/puppet/parser/functions/krb5keytab_generatekt.rb file in this module.
    #

    $keytab_content = krb5keytab_generatekt( {
      admin_keytab    => $admin_keytab_file_path,
      admin_principal => $admin_princ,
      realm           => $krb5_realm,
      admin_server    => $krb5_admin_server,
      principal       => $name,
    } )

    #
    # Apply the keytab
    #

    file { $keytab:
      path    => $keytab,
      owner   => $keytab_owner,
      group   => $keytab_group,
      mode    => $keytab_mode,
      replace => true,
      content => $keytab_content,
    }
  }
}

