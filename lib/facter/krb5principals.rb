#!/opt/puppetlabs/puppet/bin/ruby

Facter.add(:krb5principals) do
  setcode do
  princs = Hash.new
    if File.file?('/usr/bin/klist')
      output = `/usr/bin/klist -k /etc/krb5.keytab`

      output.split(/\n/).each do |line|
        if ( line =~ /^----|^KVNO|^Keytab/ )
          next
        end
        princ = line.gsub(/\s+/m, ' ').strip.split(" ")
        princs[princ[1]] = princ[0]
      end
    end
    princs
  end
end

