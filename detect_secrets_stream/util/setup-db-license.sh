#!/bin/bash -x
# Copy DB2 license file from secret into clidriver location

PIP_DIR=$(pip show ibm-db | grep Location: | awk '{print $2}')
# TODO: what if db2 license is invalid?
DB2_LICENSE_FILE=${PIP_DIR}/clidriver/license/db2consv_zs.lic
: ${DB2_SECRET_FILE:=/gd-secret/db2consv_zs.lic}

if [ -s "${DB2_SECRET_FILE}" ]; then
  cp "${DB2_SECRET_FILE}" "${DB2_LICENSE_FILE}"
else
  echo "${DB2_SECRET_FILE} does not exist or is empty."
fi
