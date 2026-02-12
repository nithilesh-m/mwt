How to start
cd node-api
npm install
npm start
cd celery-worker
python api.py
cd celery-worker
python -m celery -A celery_app worker --pool=solo --loglevel=info