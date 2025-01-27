document.getElementById('close-button').addEventListener('click', (event) => route(event));

//script to change between tabs
// Select all the tab buttons and tab panels
const tabButtons = document.querySelectorAll('[role="tab"]');
const tabPanels = document.querySelectorAll('[role="tabpanel"]');

// Function to handle tab switching
function switchTab(event) {
	// Deactivate all tabs and hide all panels
	tabButtons.forEach(button => {
		button.setAttribute('aria-selected', 'false');
	});
	tabPanels.forEach(panel => {
		panel.hidden = true;
	});

	// Activate the clicked tab
	const clickedTab = event.target;
	clickedTab.setAttribute('aria-selected', 'true');

	// Show the associated panel
	const tabPanelId = clickedTab.getAttribute('aria-controls');
	const tabPanel = document.getElementById(tabPanelId);
	tabPanel.hidden = false;
}

// Add event listeners to all tab buttons
tabButtons.forEach(button => {
	button.addEventListener('click', switchTab);
});