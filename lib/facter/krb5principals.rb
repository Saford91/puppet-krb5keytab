#!/opt/puppetlabs/puppet/bin/ruby

Facter.add(:krb5principals) do
  setcode do
    output = `/usr/bin/klist -k /etc/krb5.keytab`
    princs = Hash.new
    
    output.split(/\n/).each do |line|
      if ( line =~ /^----|^KVNO|^Keytab/ )
        next
      end
      princ = line.gsub(/\s+/m, ' ').strip.split(" ")
      princs[princ[1]] = princ[0]
    end
    princs
  end
end

