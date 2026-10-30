from django.db import models


class Report(models.Model):
    name = models.CharField(max_length=100)

    @classmethod
    def search(cls, term):
        return cls.objects.raw("SELECT * FROM app_report WHERE name LIKE '%%%s%%'" % term)
