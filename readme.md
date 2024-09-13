pip install django

django-admin startproject myproject
cd myproject
python manage.py runserver

python manage.py startapp securityServer

mkdir securityServer/views

pip install python-dotenv requests pygithub transformers
pip install pymongo
pip install python-dotenv
pip install torch torchvision torchaudio
pip install celery
pip install rabbitmq-server

celery -A apiSecurityShield worker --loglevel=info

