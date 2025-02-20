from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from ..models import Match, UserProfile

@api_view(['GET'])
def MatchHistory(request, user_id):
    """
    Récupère l'historique des matchs pour un utilisateur spécifique.
    Renvoie toutes les informations nécessaires pour créer un historique.
    """
    try:
        # Vérifier si l'utilisateur existe
        user_profile = UserProfile.objects.get(user_id=user_id)
    except UserProfile.DoesNotExist:
        return Response({
            "error": f"User with ID {user_id} does not exist."
        }, status=status.HTTP_200_OK)

    # Récupérer les matchs où l'utilisateur est impliqué (player_1 ou player_2)
    matches = Match.objects.filter(
        player_1=user_profile
    ).union(
        Match.objects.filter(player_2=user_profile)
    ).order_by('-created_at')  # Trier par date de création (les plus récents en premier)

    # Construire la réponse
    match_history = []
    for match in matches:
        match_history.append({
            "match_id": match.id,
            "player_1_id": match.player_1.user_id,
            "player_2_id": match.player_2.user_id,
            "start_time": match.match_start_time,
            "end_time": match.match_end_time,
            "score_player_1": match.score_player_1,
            "score_player_2": match.score_player_2,
            "created_at": match.created_at
        })

    return Response({
        "user_id": user_id,
        "matches": match_history
    }, status=status.HTTP_200_OK)
