#!/bin/bash

# Deployment script for FinServ Platform
# BUG: No error handling (set -e missing)
# BUG: No rollback mechanism

ENVIRONMENT=$1

if [ -z "$ENVIRONMENT" ]; then
  echo "Usage: deploy.sh <staging|production>"
  exit 1
fi

echo "Deploying to $ENVIRONMENT..."

# BUG: Using eval with user input
eval "npm run build:$ENVIRONMENT"

# SECURITY: Hardcoded server credentials
if [ "$ENVIRONMENT" == "production" ]; then
  scp -r dist/* deploy@prod-server.finserv.internal:/var/www/app/
  ssh deploy@prod-server.finserv.internal "pm2 restart finserv"
elif [ "$ENVIRONMENT" == "staging" ]; then
  scp -r dist/* deploy@staging.finserv.internal:/var/www/app/
  ssh deploy@staging.finserv.internal "pm2 restart finserv"
fi

echo "Deployment complete!"
# BUG: No health check after deployment
# BUG: No notification on deployment success/failure
