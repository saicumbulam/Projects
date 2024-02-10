$ cd ~/Desktop
$ mkdir django
$ cd django
$ pipenv install django==3.0
$ pipenv shell
(django) $ django-admin startproject test_project .
(django) $ python manage.py runserver