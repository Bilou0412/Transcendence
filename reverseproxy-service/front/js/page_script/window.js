// Get the game mode selector and the sections
const gameModeSelect = document.getElementById('gameModeSelect');
const sections = {
	"remote tournament": document.querySelector('.remoteTournament'),
	"remote 1v1": document.querySelector('.remote1v1'),
	"player vs ai": document.querySelector('.localPlayerAI'),
};

// Add an event listener for the game mode selection
gameModeSelect.addEventListener('change', function () {
	const selectedMode = gameModeSelect.value.toLowerCase();
	console.log(selectedMode);
	// Hide all sections
	Object.values(sections).forEach(section => {
		section.style.display = 'none';
	});
	console

	// Show the selected section
	if (sections[selectedMode]) {
		sections[selectedMode].style.display = 'flex';
	}
});
