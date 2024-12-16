import os
from django.conf import settings
from rest_framework.decorators import api_view
from ..decorators import authorize_user
from django.http import JsonResponse
from ..models import UserProfileImage, CustomUser
from django.core.exceptions import ObjectDoesNotExist

@api_view(['POST'])
@authorize_user
def ImageServe(request):
    user_ids = request.data.get('user_ids', [])
    images = []

    # Ensure user_ids is a list and contains valid integers
    if not isinstance(user_ids, list):
        user_ids = [user_ids]
    
    try:
        user_ids = [int(id) for id in user_ids]
    except ValueError:
        return JsonResponse({'error': 'All user_ids must be integers'}, status=400)
    

    for id in user_ids:
        try:
            user = CustomUser.objects.get(id=id)
            profile_image = UserProfileImage.objects.get(user=user)
            image_path = profile_image.image.path
            if not os.path.exists(image_path):
                images.append({'id': id, 'error': 'Image file not found'})
                continue

            content_type = None
            if image_path.lower().endswith('.jpg') or image_path.lower().endswith('.jpeg'):
                content_type = 'image/jpeg'
            elif image_path.lower().endswith('.png'):
                content_type = 'image/png'
            elif image_path.lower().endswith('.gif'):
                content_type = 'image/gif'
            
            truncated_path = image_path.split('/images/')[-1]
            image_url = request.build_absolute_uri(settings.MEDIA_URL + truncated_path)
            images.append({
                'id': id,
                'image_url': image_url,
                'content_type': content_type
            })

        except ObjectDoesNotExist:
            default_path = os.path.join('images', 'default.png')
            if os.path.exists(default_path):
                default_url = request.build_absolute_uri(settings.MEDIA_URL + 'default.png')
                images.append({
                    'id': id,
                    'image_url': default_url,
                    'content_type': 'image/png'
                })
            else:
                images.append({'id': id, 'error': 'Image file not found'})
    # print(images)
    return JsonResponse(images, safe=False)
