#!/bin/sh
HELP=NO
for i in "$@"
do
case $i in
    -d=*|--document=*)
    DOCUMENT="${i#*=}"
    shift # past argument=value
    ;;
    -s=*|--signature=*)
    SIGNATURE="${i#*=}"
    shift # past argument=value
    ;;
    -k=*|--public_key=*)
    PUBLIC_KEY="${i#*=}"
    shift # past argument=value
    ;;
    -f=*|--signature_pdf=*)
    SIGNATURE_PDF="${i#*=}"
    shift # past argument=value
    ;;
    -h|-?|--help)
    HELP=YES
    shift # past argument with no value
    ;;
    *)
            # unknown option
    ;;
esac
done

if [[ $HELP = YES ]]
then
	echo "
\x1B[1mUsage:\x1B[0m ./verify.sh [-d=[FILE] -s=[FILE] -k=[FILE] -f=[FILE]]|[-h]

-d=[FILE]|--document=[FILE]
	[FILE] is the original document to be signed

-s=[FILE]|--signature=[FILE]
	[FILE] is the signature received along with the signature PDF page

-k=[FILE]|--public_key=[FILE]
	[FILE] is the public key in PEM format received along with the signature PDF page

-f=[FILE]|--signature_pdf=[FILE]
	[FILE] is the signature PDF that contains the face and/or ID card of the signer

-h|-?|--help
	Print this help
"
	exit
fi

if [[ "${DOCUMENT}" == "" ]]; then
	echo "Missing document parameter"
	exit 1
fi

if [[ "${SIGNATURE}" == "" ]]; then
	echo "Missing signature parameter"
	exit 1
fi

if [[ "${PUBLIC_KEY}" == "" ]]; then
	echo "Missing public key parameter"
	exit 1
fi

if [[ "${SIGNATURE_PDF}" == "" ]]; then
	echo "Missing signature PDF parameter"
	exit 1
fi

HASH=`md5sum "${DOCUMENT}" | sed "s|  ${DOCUMENT}||"`
echo "Document hash: $HASH"

PDFTXT="$HASH.txt"

pdftotext "${SIGNATURE_PDF}" "${PDFTXT}"

if grep -q "$HASH" "${PDFTXT}"; then
	echo "Found document hash in PDF"
else
	echo "Document hash not found in PDF"
	exit 2
fi

openssl dgst -sha256 -verify "${PUBLIC_KEY}" -signature "${SIGNATURE}" "${SIGNATURE_PDF}"