#!/opt/puppetlabs/puppet/bin/ruby

Facter.add(:krb5principals) do
  setcode do
  princs = Array.new
    if File.file?('/usr/bin/klist')
      output = `/usr/bin/klist -k /etc/krb5.keytab`

      output.split(/\n/).each do |line|
        if ( line =~ /^----|^KVNO|^Keytab/ )
          next
        end
        princ = line.gsub(/\s+/m, ' ').strip.split(" ")
        princs.push(princ[1].split('@')[0])
      end
    end
    p princs.uniq
  end
end

