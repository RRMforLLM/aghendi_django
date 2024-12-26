from django.core.management.base import BaseCommand
from django.utils import timezone
from aghendi.models import AgendaElement
from datetime import timedelta

class Command(BaseCommand):
    help = 'Deletes or marks expired agenda elements.'

    def handle(self, *args, **kwargs):
        now = timezone.now()

        expired_elements = AgendaElement.objects.filter(deadline__lt=now)

        for element in expired_elements:
            element.delete()

            self.stdout.write(self.style.SUCCESS(f'Deleted expired element: {element.subject}'))

        self.stdout.write(self.style.SUCCESS('Expired elements cleanup completed.'))