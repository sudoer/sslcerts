#!/bin/bash

caname='apca'
subj='/C=US/ST=NC/O=alanporter.com/localityName=Cary/commonName=COMMON/organizationalUnitName=alanporter.com' # /emailAddress=certs@alanporter.com'
cabits=8192
cadays=$((365*30))
signbits=2048
signdays=$((365*1))

arg0=$(basename $0)

#-------------------------------------------------------------------------------

function make_ca_config_file () {
    cfgfile=$(mktemp /tmp/openssl.XXXXXX)
    cat > $cfgfile << EOF
    [ ca ]
    default_ca = ca_alan

    [ ca_alan ]
    dir             = db                      # Where everything is kept
    crl_dir         = \$dir/crl               # Where the issued crl are kept
    database        = \$dir/index.txt         # database index file.
    new_certs_dir   = \$dir/newcerts          # default place for new certs.
    serial          = \$dir/serial.txt        # The current serial number
    crlnumber       = \$dir/crlnumber         # the current crl number, must be commented out to leave a V1 CRL
    crl             = \$dir/crl.pem           # The current CRL
    certificate     = \$dir/$caname-pub.pem   # The CA certificate
    private_key     = \$dir/$caname-pri.pem   # The private key

    ##certs           = \$dir/certs           # Where the issued certs are kept
    ## RANDFILE        = \$dir/private/.rand  # private random number file

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
    default_md      = md5                   # ALAN: was 'default'
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
}

#-------------------------------------------------------------------------------

function usage () {
    echo "$arg0 initca"
    echo "$arg0 domaincert example.com www.example.com example2.org www.example2.org"
    echo "$arg0 sign csrfile.csr"
}

#-------------------------------------------------------------------------------

function init_cert_auth () {
    echo "init_cert_auth"

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
        openssl req -new -nodes -passin pass:$passphrase -key $caname.key -subj "${subj/COMMON/ca.alanporter.com}" -out $caname.csr
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
    [ -d db ] || mkdir db
    [ -d db/crl ] || mkdir db/crl
    [ -d db/newcerts ] || mkdir db/newcerts
    touch db/index.txt
    [ -f db ] || echo 'unique_subject = no' > db/index.txt.attr
    [ -f db/$caname-pub.pem ] || cat $caname.pem > db/$caname-pub.pem
    [ -f db/$caname-pri.pem ] || cat $caname.key > db/$caname-pri.pem

    # we will sign our own certificate as serial number one
    if [ ! -f db/serial.txt ] ; then
        echo '02' > db/serial.txt
    fi
}

#-------------------------------------------------------------------------------

function domain_cert () {
    domains=$*
    echo "domaincert $domains"

    echo -n "enter passphrase (will be shown): "
    read passphrase

    HOSTNAMES=($domains)
    primaryDomain=${HOSTNAMES[0]}

    if [[ ${#HOSTNAMES[@]} -eq 0 ]] ; then
        # no hostnames specified
        echo "you must specify one or more hostnames (may contain stars)"
        exit 1
    elif [[ ${#HOSTNAMES[@]} -eq 1 ]] ; then
        # 1 hostname specified
        ##OLD  CNSTUFF='
        ##OLD      commonName = Common Name (eg, YOUR name)
        ##OLD      commonName_max = 64'
        SAN=''
    else
        # >1 hostnames specified
        ##OLD  CNSTUFF=''
        for i in $( seq 0 $(( ${#HOSTNAMES[@]} - 1 )) )
        do
            ##OLD  CNSTUFF="$CNSTUFF
            ##OLD     $i.commonName = Common Name (eg, YOUR name)
            ##OLD     $i.commonName_default = www.domain$i.com
            ##OLD     $i.commonName_max = 64"
            SAN="${SAN},DNS:${HOSTNAMES[$i]}"
        done
        ##OLD  CNSTUFF='
        ##OLD      commonName = Common Name (eg, YOUR name)
        ##OLD      commonName_max = 64'
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
    [ req_distinguished_name ]
    # countryName = Country Name (2 letter code)
    # countryName_default = AU
    # countryName_min = 2
    # countryName_max = 2
    # stateOrProvinceName = State or Province Name (full name)
    # stateOrProvinceName_default = Some-State
    # localityName = Locality Name (eg, city)
    # 0.organizationName = Organization Name (eg, company)
    # 0.organizationName_default = Internet Widgits Pty Ltd
    # organizationalUnitName = Organizational Unit Name (eg, section)
    # ${CNSTUFF}
    # emailAddress = Email Address
    # emailAddress_max = 64
EOF

    # generate a CSR (certificate signing request)
    if [ -f $primaryDomain.csr ] ; then
        echo "using existing signing request file '$primaryDomain.csr'"
    else
        openssl req -config $cfgfile -new -nodes -passin pass:$passphrase -key $primaryDomain.key -subj "${subj/COMMON/$primaryDomain}" -out $primaryDomain.csr
    fi

    # self-sign the certificate
    if [ -f $primaryDomain.crt ] ; then
        echo "using existing certificate file '$primaryDomain.crt'"
    else
        openssl x509 -req -days $signdays -passin pass:$passphrase -in $primaryDomain.csr -signkey $primaryDomain.key -out $primaryDomain-self.crt
    fi
}

#-------------------------------------------------------------------------------

function sign () {
    csrfile=$1
    echo "sign $csrfile"

    domain=${csrfile%.csr}

    if [ -f $domain-$caname.crt ] ; then
        echo "refusing to cover up existing certificate file '$domain-$caname.crt'"
    else
        make_ca_config_file
        openssl ca -config $cfgfile -in $domain.csr -days $signdays -out $domain-$caname.crt
    fi
}

#-------------------------------------------------------------------------------

# COMMAND-LINE ARGUMENTS
while [ "$1" != "" ]; do
    case $1 in
#       -f | --file )
#           shift
#           filename=$1
#           ;;
#       -i | --interactive )
#           interactive=1
#           ;;
        -h | --help )
            shift
            usage
            exit 0
            ;;
        initca )
            shift
            init_cert_auth
            exit 0
            ;;
        domaincert )
            shift
            domain_cert $*
            exit 0
            ;;
        sign )
            shift
            sign $*
            exit 0
            ;;
        * )
            usage
            exit 1
    esac
    shift
done


if [ -f "$cfgfile" ] ; then rm $cfgfile ; fi
echo "done"
exit 0



