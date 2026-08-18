const React = require('react');
const ReactDOMServer = require('react-dom/server');
const sharp = require('sharp');
const fs = require('fs');
const Fa = require('react-icons/fa');

const jobs = [
  ['FaShieldAlt', '1C7293'],
  ['FaSearch', '065A82'],
  ['FaRobot', '065A82'],
  ['FaDatabase', '065A82'],
  ['FaCode', '1C7293'],
  ['FaChartBar', '1C7293'],
  ['FaExclamationTriangle', 'B03A2E'],
  ['FaClock', '1C7293'],
  ['FaUsers', '065A82'],
  ['FaLightbulb', 'C97A2B'],
  ['FaListUl', '065A82'],
  ['FaCogs', '1C7293'],
  ['FaCheckCircle', '2E8B57'],
  ['FaProjectDiagram', '065A82'],
  ['FaBrain', '1C7293'],
  ['FaBookOpen', '065A82'],
  ['FaSitemap', '1C7293'],
  // white variants for dark backgrounds
  ['FaShieldAlt', 'FFFFFF', 'white'],
  ['FaUsers', 'FFFFFF', 'white'],
  ['FaGithub', 'FFFFFF', 'white'],
];

(async () => {
  for (const [name, color, suffix] of jobs) {
    const Icon = Fa[name];
    const svgMarkup = ReactDOMServer.renderToStaticMarkup(
      React.createElement(Icon, { color: `#${color}`, size: 256 })
    );
    const inner = svgMarkup.replace(/^<svg[^>]*>/, '').replace(/<\/svg>$/, '');
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="256" height="256" fill="#${color}">${inner}</svg>`;
    const outName = `icon_${name}${suffix ? '_' + suffix : ''}.png`;
    await sharp(Buffer.from(svg)).resize(256, 256).png().toFile(outName);
    console.log('wrote', outName);
  }
})();
