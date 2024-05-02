if (window.location.pathname == '/dashboard') {
    document.addEventListener('DOMContentLoaded', onLoad);
}
// Function to generate a random hex color within a specified range
function generateColor(min, max) {
    let color = Math.floor(Math.random() * (max - min + 1)) + min;
    return color.toString(16).padStart(2, '0'); // Convert to hex and pad with zero if needed
}

// Function to create a color within the pink, purple, and blue spectrum
function getRandomColor() {
    // Define RGB ranges for pink, purple, and blue
    const pinkRange = { r: [230, 255], g: [50, 180], b: [170, 255] };
    const purpleRange = { r: [128, 160], g: [0, 80], b: [128, 180] };
    const blueRange = { r: [0, 100], g: [0, 180], b: [200, 255] };

    // Randomly choose one of the ranges
    const chosenRange = [pinkRange, purpleRange, blueRange][Math.floor(Math.random() * 3)];

    // Generate each color component based on the chosen range
    const r = generateColor(...chosenRange.r);
    const g = generateColor(...chosenRange.g);
    const b = generateColor(...chosenRange.b);

    return { hex: `#${r}${g}${b}`, rgb: { r: parseInt(r, 16), g: parseInt(g, 16), b: parseInt(b, 16) } };
}

// Function to calculate luminance and decide text color
function getTextColor({ r, g, b }) {
    // Using the luminance formula to find the appropriate text color
    const luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b;
    return luminance > 128 ? 'black' : 'white';
}

function onLoad() {
    var totalsBar = document.getElementById('totalsBar');
    var sections = totalsBar.querySelectorAll('.totalsSection');

  


    // loop over sections 
    sections.forEach(section => {
        const color = getRandomColor();
        section.style.flexGrow = section.innerHTML;
        section.style.backgroundColor = color.hex;
        section.style.color = getTextColor(color.rgb);
        section.style.display = 'flex';

    });





}