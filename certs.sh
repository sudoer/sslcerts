#!/bin/bash

# This script is used to create domain certificates, and also to
# create a CA certificate and to sign domain certs using the CA.
# It handles multi-domain certificates (using the subjectAltName
# field).   - Alan Porter, 2014-12-31

# Customize this stuff by creating a file called '$HOME/.certs.cfg' or
# '/etc/certs.cfg' with your own values.  Use bash notation.  It'll
# be sourced in here.
caname='example'
cacn='ca.example.com'
cabits=4096
cadays=$((365*30))
signbits=2048
signdays=$((365*1))

# Everything from here on down should not need modification.
#-------------------------------------------------------------------------------
# Note - This script does not rely on any environment variables or any
# openssl.conf file.  Surprisingly, most tutorials I have found online
# leave out some important detail that is buried in the author's config
# files.  This script creates the config files that it needs on the fly.
#-------------------------------------------------------------------------------

function do_initca () {
    caname=$1
    subj=$2
    email=$3
    echo "do_initca"
    echo "  CA name = '$caname'"
    echo "  subject = '$subj'"
    echo "  email = '$email'"

    echo -n "enter passphrase (will be shown): "
    read passphrase

    # generate a private RSA key
    if [ -f $caname.key ] ; then
        echo "using existing key file '$caname.key'"
    else
        openssl genrsa -des3 -passout pass:$passphrase -out $caname.key $cabits
    fi
    chmod 400 $caname.key

    # generate a CSR (certificate signing request)
    if [ -f $caname.csr ] ; then
        echo "using existing signing request file '$caname.csr'"
    else
        openssl req -new -nodes -passin pass:$passphrase -key $caname.key -subj "${subj/COMMON/$cacn}" -out $caname.csr
    fi

    # self-sign the certificate
    if [ -f $caname.crt ] ; then
        echo "using existing certificate file '$caname.crt'"
    else
        openssl x509 -req -days $cadays -passin pass:$passphrase -in $caname.csr -signkey $caname.key -set_serial 01 -CAcreateserial -CAserial db/serial.txt -out $caname.crt
    fi

    # make a pretty version of the cert that we will share
    if [ -f $caname.pem ] ; then
        echo "using existing 'pretty' certificate file '$caname.pem'"
    else
        openssl x509 -in $caname.crt -text > $caname.pem
    fi

    # create the CA file structure
    db="$caname-info"
    [ -d $db ] || mkdir $db
    [ -d $db/crl ] || mkdir $db/crl
    [ -d $db/newcerts ] || mkdir $db/newcerts
    touch $db/index.txt
    [ -f $db ] || echo 'unique_subject = no' > $db/index.txt.attr
    [ -f $db/$caname-pub.pem ] || cat $caname.pem > $db/$caname-pub.pem
    [ -f $db/$caname-pri.pem ] || cat $caname.key > $db/$caname-pri.pem

    # we will sign our own certificate as serial number one
    if [ ! -f $db/serial.txt ] ; then
        echo '02' > $db/serial.txt
    fi
}

#-------------------------------------------------------------------------------

function do_domaincert () {
    subj=$1
    email=$2
    HOSTNAMES=($(echo $3 | tr ',' ' '))
    echo "do_domaincert"
    echo "  subject = '$subj'"
    echo "  email = '$email'"
    for i in $( seq 0 $(( ${#HOSTNAMES[@]} - 1 )) ) ; do
        echo -n "  domain = '${HOSTNAMES[$i]}'"
        [[ $i == 0 ]] && echo -n " (primary)"
        echo ""
    done

    primaryDomain=${HOSTNAMES[0]}

    echo -n "enter passphrase (will be shown): "
    read passphrase

    if [[ ${#HOSTNAMES[@]} -eq 0 ]] ; then
        # no hostnames specified
        echo "you must specify one or more hostnames (may contain stars)"
        exit 1
    elif [[ ${#HOSTNAMES[@]} -eq 1 ]] ; then
        # 1 hostname specified
        SAN=''
    else
        # >1 hostnames specified
        for i in $( seq 0 $(( ${#HOSTNAMES[@]} - 1 )) ) ; do
            SAN="${SAN},DNS:${HOSTNAMES[$i]}"
        done
        SAN="subjectAltName=\"${SAN#,}\""
        echo "san>>$SAN"
    fi

    # generate a private RSA key
    if [ -f $primaryDomain.key ] ; then
        echo "using existing key file '$primaryDomain.key'"
    else
        openssl genrsa -des3 -passout pass:$passphrase -out $primaryDomain.key $signbits
    fi
    chmod 400 $primaryDomain.key

    # put the SAN info in the openssl config file, needed for the request
    cfgfile=$(mktemp /tmp/openssl.XXXXXX)
    cat > $cfgfile << EOF
    [ req ]
    distinguished_name = req_distinguished_name
    req_extensions = v3_req
    [ v3_req ]
    basicConstraints = CA:FALSE
    keyUsage = nonRepudiation, digitalSignature, keyEncipherment
    ${SAN}
EOF

    # generate a CSR (certificate signing request)
    if [ -f $primaryDomain.csr ] ; then
        echo "using existing signing request file '$primaryDomain.csr'"
    else
        openssl req -config $cfgfile -new -nodes -passin pass:$passphrase -key $primaryDomain.key -subj "$subj/CN=$primaryDomain" -out $primaryDomain.csr
    fi

    # self-sign the certificate
    if [ -f $primaryDomain.crt ] ; then
        echo "using existing certificate file '$primaryDomain.crt'"
    else
        openssl x509 -req -days $signdays -passin pass:$passphrase -in $primaryDomain.csr -signkey $primaryDomain.key -out $primaryDomain-self.crt
    fi
}

#-------------------------------------------------------------------------------

function do_sign () {
    csrfile=$1
    caname=$2
    echo "do_sign"
    echo "  CSR file = '$csrfile'"
    echo "  CA name = '$caname'"

    domain=${csrfile%.csr}

    if [ -f $domain-$caname.crt ] ; then
        echo "refusing to cover up existing certificate file '$domain-$caname.crt'"
        exit 2
    fi

    db="$caname-info"
    cfgfile=$(mktemp /tmp/openssl.XXXXXX)
    cat > $cfgfile << EOF
    [ ca ]
    default_ca = ca_mine

    [ ca_mine ]
    dir             = $db   # Where everything is kept
    crl_dir         = \$dir/crl               # Where the issued crl are kept
    database        = \$dir/index.txt         # database index file.
    new_certs_dir   = \$dir/newcerts          # default place for new certs.
    serial          = \$dir/serial.txt        # The current serial number
    crlnumber       = \$dir/crlnumber         # the current crl number, must be commented out to leave a V1 CRL
    crl             = \$dir/crl.pem           # The current CRL
    certificate     = \$dir/$caname-pub.pem   # The CA certificate
    private_key     = \$dir/$caname-pri.pem   # The private key

    ## certs           = \$dir/certs             # Where the issued certs are kept
    ## RANDFILE        = \$dir/private/.rand     # private random number file

    x509_extensions = usr_cert               # The extentions to add to the cert

    # Comment out the following two lines for the "traditional" (and highly broken) format.
    name_opt        = ca_default            # Subject Name options
    cert_opt        = ca_default            # Certificate field options

    # Extension copying option: use with caution.
    # ALAN - needed to copy subjectAltName from request into generated certificate.
    copy_extensions = copy

    # Extensions to add to a CRL. Note: Netscape communicator chokes on V2 CRLs
    # so this is commented out by default to leave a V1 CRL.
    # crlnumber must also be commented out to leave a V1 CRL.
    # crl_extensions        = crl_ext

    default_days    = 365                   # how long to certify for
    default_crl_days= 30                    # how long before next CRL
    default_md      = sha1                  # ALAN: was 'default'
    preserve        = no                    # keep passed DN ordering

    # A few difference way of specifying how similar the request should look
    # For type CA, the listed attributes must be the same, and the optional
    # and supplied fields are just that :-)
    policy          = policy_anything

    # what is this?
    email_in_dn = no

    #-------------------------------------------------------------------

    [ usr_cert ]
    # needed because copy_extensions = copy and we don't want client to request a CA cert from us
    basicConstraints = CA:FALSE

    # PKIX recommendations harmless if included in all certificates.
    subjectKeyIdentifier=hash
    authorityKeyIdentifier=keyid,issuer

    #-------------------------------------------------------------------

    # For the 'anything' policy
    # At this point in time, you must list all acceptable 'object'
    # types.
    [ policy_anything ]
    countryName             = optional
    stateOrProvinceName     = optional
    localityName            = optional
    organizationName        = optional
    organizationalUnitName  = optional
    commonName              = supplied
    emailAddress            = optional
EOF

    openssl ca -config $cfgfile -in $domain.csr -days $signdays -out $domain-$caname.crt
    openssl x509 -in $domain-$caname.crt -text | awk '/^Certificate/,/^---/' | grep -v '^ .*:$' | sed 's/^/CERT>> /g'
}

#-------------------------------------------------------------------------------

function usage () {
    echo "usage:"
    echo ""

    subj='/C=US/ST=NC/L=Cary/O=example.com/OU=ca.example.com/CN=ca.example.com'
    echo "TO CREATE A CERTIFICATE AUTHORITY"
    echo "  $arg0 initca <ca> <subj> <email>"
    echo "  $arg0 initca myCAname '$subj' certs@ca.example.com"
    echo "  where C = country, ST = state, L = location/city, O = organization, OU = organization unit"
    echo "  and CN = common name (the name of the certificate authority)"
    echo ""

    subj='/C=US/ST=NC/L=Cary/O=example.com/OU=example.com'
    echo "TO CREATE A DOMAIN CERTIFICATE"
    echo "  $arg0 domaincert <subj> <email> <domain1>[,<domain2>][,...]"
    echo "  $arg0 domaincert '$subj' domain@example.com example.com,www.example.com,example2.org,www.example2.org"
    echo "  where C = country, ST = state, L = location/city, O = organization, OU = organization unit"
    echo "  CN will be filled in using the first domain name"
    echo "  domains are comma-separated, no spaces"
    echo ""

    echo "TO SIGN A DOMAIN CERTIFICATE WITH A CA CERT"
    echo "  $arg0 sign <csrfile> <ca>"
    echo "  $arg0 sign csrfile.csr myCAname"
    echo ""
}

#-------------------------------------------------------------------------------

# START
arg0=$(basename $0)
for cfgfile in /etc/certs.cfg $HOME/.certs.cfg ; do
    [[ -f $cfgfile ]] && echo "reading $cfgfile" && source $cfgfile
done

# COMMAND-LINE ARGUMENTS
case $1 in
    -h | --help | help )
        usage
        ;;
    initca )
        shift
        do_initca $*
        ;;
    domaincert )
        shift
        do_domaincert $*
        ;;
    sign )
        shift
        do_sign $*
        ;;
    * )
        usage
        exit 1
esac

if [ -f "$cfgfile" ] ; then rm $cfgfile ; fi
echo "done"
exit 0


