# yourapp/management/commands/createsuperuser_custom.py
from django.core.management.base import BaseCommand
from ki.models import User


class Command(BaseCommand):
    def handle(self, *args, **options):
        username = "admin"
        password = "admin"

        if not User.objects.filter(username=username).exists():
            User.objects.create_superuser(username, password)
            self.stdout.write(self.style.SUCCESS("Superuser created successfully"))
        else:
            self.stdout.write(self.style.WARNING("Superuser already exists"))
