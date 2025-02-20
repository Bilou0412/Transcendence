export const pongBindings = {
    player1UpBind: 'w',
    player1DownBind: 's',
    player2UpBind: 'ArrowUp',
    player2DownBind: 'ArrowDown'
};

export const pongColors = {
    player1Side: 0x222222,
    player2Side: 0x222222,
    player1Paddle: 0x797979,
    player2Paddle: 0x797979
};

export const pongSet = {
    selectedMode: 'local 1v1',
    current_match: 1,
    players_names: ["player 1", "player 2", "player 3", "player 4", null, null, null],
};

export function getMatchWinners() {
    const semifinal1Winner = document.getElementById('semifinal1');
    const semifinal2Winner = document.getElementById('semifinal2');
    const finalWinner = document.getElementById('final');

    if (semifinal1Winner && semifinal2Winner && finalWinner) {
        return { semifinal1Winner, semifinal2Winner, finalWinner };
    }
    
    return null;
}