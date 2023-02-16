from django.db.models.signals import post_save
from django.db.models.signals import post_save
from django.dispatch import receiver
from allauth.socialaccount.models import SocialLogin# step 3 made this possible
from django.contrib.auth.models import User

@receiver(post_save, sender = SocialLogin)
def create_profile(sender, instance, created, **kwargs):
    print("thingy")