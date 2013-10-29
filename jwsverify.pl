#!/usr/bin/perl 

#
# jwsverify.pl - JSON Web Signature Verifier
#

# USAGE:
#
# % jwsverify.pl JWSFILE PKCS8PUBLICKEYPEMFILE
#
# Verified OK  
# .. or ..
# Verification Failure

my $VERSION = "1.0.0";

my $jwsFile = $ARGV[0];
my $pubKey = $ARGV[1];

sub _saveEsAsn1Sig {
    my ($sigFile, $asn1SigFile) = @_;
    my $s = "";
    open(FIN, $sigFile) or die;
    while (<FIN>) {
	$s .= $_;
    }
    close FIN;

    my $n = length($s);
    my $sig1 = substr($s, 0, $n / 2);
    my $sig2 = substr($s, $n / 2, $n / 2);
    #print "sig1[0] = ", ord(substr($sig1, 0, 1)), "\n";
    #print "sig2[0] = ", ord(substr($sig2, 0, 1)), "\n";
    $sig1 = "\0" . $sig1 if ord(substr($sig1, 0, 1)) > 127;
    $sig2 = "\0" . $sig2 if ord(substr($sig2, 0, 1)) > 127;
    my $sig1der = chr(2) . chr(length($sig1)) . $sig1;
    my $sig2der = chr(2) . chr(length($sig2)) . $sig2;
    my $n2 = length($sig1der) + length($sig2der);
    #print "n2 = ", $n2, "\n";
    my $L = "";
    if ($n2 > 127) {
	$L = chr(129) . chr($n2);
    } else {
	$L = chr($n2);
    }
    my $sigder = chr(48) . $L . $sig1der . $sig2der;
    
    open(FOUT, "> $asn1SigFile") or die;
    print FOUT $sigder;
    close FOUT;
}

sub _saveSigBin {
    my ($sigB64U, $fileSig) = @_;
    my $tmpFile = $fileSig . ".b64";
    &_saveBase64File($sigB64U, $tmpFile);
    system "openssl base64 -d -in $tmpFile -out $fileSig";
    unlink $tmpFile;
};

sub _saveSI {
    my ($headB64U, $payloadB64U, $fileName) = @_;
    open(FOUT, "> $fileName") or die;
    print FOUT $headB64U . "." . $payloadB64U;
    close FOUT;
}

sub _getAlg {
    my ($headB64U) = @_;
    my $tmpFile = "/tmp/jv.head.$$";
    &_saveHead($headB64U, $tmpFile);
    
    my $s = "";
    open(FIN, $tmpFile) or die;
    while (<FIN>) {
	$s .= $_;
    }
    close FIN;
    unlink $tmpFile;

    my $alg = "";
    if ($s =~ /['"]alg['"]\s*:\s*['"]([EPR]S\d{3})['"]/) {
	$alg = $1;
    }
    return $alg;
}

sub _saveHead {
    my ($headB64U, $fileName) = @_;
    &_saveBase64File($headB64U, $fileName . ".b64");
    system "openssl base64 -d -in ${fileName}.b64 -out ${fileName}";
    unlink $fileName . ".b64";
};

sub _saveBase64File {
    my ($base64u, $fileName) = @_;
    $base64u =~ s/-/+/g;
    $base64u =~ s/_/\//g;
    my $padlen = 4 - (length($base64u) % 4);
    $padlen = 0 if $padlen == 4;
    $base64u .= "=" if $padlen == 1;
    $base64u .= "==" if $padlen == 2;
    $base64u .= "===" if $padlen == 3;

    my $s = $base64u;
    my $r = "";
    while (($s1, $s2) = ($s =~ /^(.{64})(.*)$/)) {
	$r .= $s1 . "\r\n";
	$s = $s2;
    }
    $r .= $s . "\r\n";

    open(FOUT, "> $fileName") or die;
    print FOUT $r;
    close(FOUT);
};

my $jws = "";
open(FIN, $jwsFile) or die;
while (<FIN>) {
    $jws .= $_;
}
close FIN;

#print $jws, "\n";

my ($headB64U, $payloadB64U, $sigB64U) = ($jws =~ /^(.+)\.(.+)\.(.+)$/);
#print $headB64U, "\n";
#print $payloadB64U, "\n";
#print $sigB64U, "\n";

my $alg = _getAlg($headB64U);
#print "alg = ", $alg, "\n";

my $fileSI = "/tmp/jv.SI.$$";
my $fileSig = "/tmp/jv.Sig.$$";

&_saveSI($headB64U, $payloadB64U, $fileSI);
&_saveSigBin($sigB64U, $fileSig);

my ($algType, $algSize) = ($alg =~ /^(..)(\d{3})$/);

if ($algType eq "PS") {
    system "openssl dgst -sha${algSize} -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -verify $pubKey -signature $fileSig $fileSI";
} elsif ($algType eq "RS") {
    system "openssl dgst -sha${algSize} -verify $pubKey -signature $fileSig $fileSI";
} elsif ($algType eq "ES") {
    my $asn1SigFile = $fileSig . ".asn1";
    &_saveEsAsn1Sig($fileSig, $asn1SigFile);
    system "openssl dgst -sha${algSize} -verify $pubKey -signature $asn1SigFile $fileSI";
    unlink $asn1SigFile;
} else {
    print "error: alg ${alg} not supported\n";
}

unlink $fileSI;
unlink $fileSig;

