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
# This class manages creating kerberos principals and adding them to
# /etc/krb5.keytab
# -----------------
# Requires stdlib

class krb5keytab (
  $admin_keytab      = undef,
  $admin_princ       = undef,
  $krb5_realm        = undef,
  $krb5_admin_server = undef,
  $keytab            = '/etc/krb5.keytab',
  $keytab_owner      = 'root',
  $keytab_group      = 'root',
  $keytab_mode       = '0600',
  $principals        = hiera_array("krb5keytab::keytab::principals"),
) {
  
  validate_absolute_path($keytab)

  #
  # Build/obtain the keytab
  #
  
  notice("principals : ${principals}")
  notice("krb5principals : ${::krb5principals}")


  if ($::krbprincipals == unique(concat($principals, $::krb5principals))) {

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
      principals      => $principals,
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

