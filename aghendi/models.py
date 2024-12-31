from django.db import models
from django.contrib.auth.models import User

class Agenda(models.Model):
    name = models.CharField(max_length=100, unique=True)
    key = models.CharField(max_length=100)
    key_visible = models.BooleanField(default=False)
    creator = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_agendas')
    editors = models.ManyToManyField(User, related_name="edited_agendas", blank=True)
    members = models.ManyToManyField(User, related_name='joined_agendas', blank=True)

    def __str__(self):
        return self.name

class AgendaSection(models.Model):
    name = models.CharField(max_length=100)
    agenda = models.ForeignKey(Agenda, on_delete=models.CASCADE, related_name='sections')

    def __str__(self):
        return f"{self.agenda.name} - {self.name}"

class AgendaElement(models.Model):
    section = models.ForeignKey(AgendaSection, on_delete=models.CASCADE, related_name='elements')
    subject = models.CharField(max_length=200)
    details = models.TextField()
    deadline = models.DateField(null=True, blank=True)
    emission = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=20, default='active', choices=[('active', 'Active'), ('expired', 'Expired')])
    completed = models.ManyToManyField(User, related_name='flagged_completed', blank=True)
    urgent = models.ManyToManyField(User, related_name='flagged_urgent', blank=True)
    nothing = models.ManyToManyField(User, related_name='not_flagged')

    def __str__(self):
        return self.subject

class ElementComment(models.Model):
    element = models.ForeignKey(AgendaElement, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Comment by {self.user.username} on {self.element.subject}"