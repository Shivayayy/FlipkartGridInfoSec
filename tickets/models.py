from django.db import models

class Ticket(models.Model):
    ticket_id = models.CharField(max_length=255, unique=True)
    endpoint = models.CharField(max_length=255)
    title = models.CharField(max_length=255)
    risk = models.CharField(max_length=50)
    status = models.CharField(max_length=50, default='OPEN')
    description = models.TextField()

    def __str__(self):
        return self.ticket_id
