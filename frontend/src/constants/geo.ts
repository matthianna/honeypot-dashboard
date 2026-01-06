// Country coordinates for map plotting
// Centralized to avoid duplication across components

export const COUNTRY_COORDS: Record<string, [number, number]> = {
  'United States': [37.0902, -95.7129],
  'USA': [37.0902, -95.7129],
  'US': [37.0902, -95.7129],
  'China': [35.8617, 104.1954],
  'Russia': [61.524, 105.3188],
  'Russian Federation': [61.524, 105.3188],
  'Germany': [51.1657, 10.4515],
  'France': [46.6034, 1.8883],
  'United Kingdom': [55.3781, -3.436],
  'UK': [55.3781, -3.436],
  'Great Britain': [55.3781, -3.436],
  'Netherlands': [52.1326, 5.2913],
  'The Netherlands': [52.1326, 5.2913],
  'Brazil': [-14.235, -51.9253],
  'India': [20.5937, 78.9629],
  'South Korea': [35.9078, 127.7669],
  'Republic of Korea': [35.9078, 127.7669],
  'Korea, Republic of': [35.9078, 127.7669],
  'Japan': [36.2048, 138.2529],
  'Vietnam': [14.0583, 108.2772],
  'Viet Nam': [14.0583, 108.2772],
  'Indonesia': [-0.7893, 113.9213],
  'Singapore': [1.3521, 103.8198],
  'Taiwan': [23.6978, 120.9605],
  'Taiwan, Province of China': [23.6978, 120.9605],
  'Hong Kong': [22.3193, 114.1694],
  'Canada': [56.1304, -106.3468],
  'Australia': [-25.2744, 133.7751],
  'Italy': [41.8719, 12.5674],
  'Spain': [40.4637, -3.7492],
  'Poland': [51.9194, 19.1451],
  'Ukraine': [48.3794, 31.1656],
  'Romania': [45.9432, 24.9668],
  'Bulgaria': [42.7339, 25.4858],
  'Turkey': [38.9637, 35.2433],
  'Türkiye': [38.9637, 35.2433],
  'Iran': [32.4279, 53.688],
  'Iran, Islamic Republic of': [32.4279, 53.688],
  'Pakistan': [30.3753, 69.3451],
  'Thailand': [15.87, 100.9925],
  'Malaysia': [4.2105, 101.9758],
  'Argentina': [-38.4161, -63.6167],
  'Mexico': [23.6345, -102.5528],
  'Colombia': [4.5709, -74.2973],
  'Chile': [-35.6751, -71.543],
  'South Africa': [-30.5595, 22.9375],
  'Nigeria': [9.082, 8.6753],
  'Egypt': [26.8206, 30.8025],
  'Morocco': [31.7917, -7.0926],
  'Kenya': [-0.0236, 37.9062],
  'Switzerland': [46.8182, 8.2275],
  'Austria': [47.5162, 14.5501],
  'Belgium': [50.5039, 4.4699],
  'Sweden': [60.1282, 18.6435],
  'Norway': [60.472, 8.4689],
  'Denmark': [56.2639, 9.5018],
  'Finland': [61.9241, 25.7482],
  'Ireland': [53.4129, -8.2439],
  'Portugal': [39.3999, -8.2245],
  'Greece': [39.0742, 21.8243],
  'Czech Republic': [49.8175, 15.473],
  'Czechia': [49.8175, 15.473],
  'Hungary': [47.1625, 19.5033],
  'Philippines': [12.8797, 121.774],
  'Bangladesh': [23.685, 90.3563],
  'Saudi Arabia': [23.8859, 45.0792],
  'United Arab Emirates': [23.4241, 53.8478],
  'Israel': [31.0461, 34.8516],
  'New Zealand': [-40.9006, 174.886],
  'Peru': [-9.19, -75.0152],
  'Venezuela': [6.4238, -66.5897],
  'Ecuador': [-1.8312, -78.1834],
  'Lithuania': [55.1694, 23.8813],
  'Latvia': [56.8796, 24.6032],
  'Estonia': [58.5953, 25.0136],
  'Slovakia': [48.669, 19.699],
  'Slovenia': [46.1512, 14.9955],
  'Croatia': [45.1, 15.2],
  'Serbia': [44.0165, 21.0059],
  'Belarus': [53.7098, 27.9534],
  'Moldova': [47.4116, 28.3699],
  'Moldova, Republic of': [47.4116, 28.3699],
  'Georgia': [42.3154, 43.3569],
  'Azerbaijan': [40.1431, 47.5769],
  'Kazakhstan': [48.0196, 66.9237],
  'Uzbekistan': [41.3775, 64.5853],
  'Sri Lanka': [7.8731, 80.7718],
  'Nepal': [28.3949, 84.124],
  'Cambodia': [12.5657, 104.991],
  'Myanmar': [21.9162, 95.956],
  'Laos': [19.8563, 102.4955],
  "Lao People's Democratic Republic": [19.8563, 102.4955],
  'Mongolia': [46.8625, 103.8467],
  'North Korea': [40.3399, 127.5101],
  "Korea, Democratic People's Republic of": [40.3399, 127.5101],
  'Algeria': [28.0339, 1.6596],
  'Tunisia': [33.8869, 9.5375],
  'Libya': [26.3351, 17.2283],
  'Sudan': [12.8628, 30.2176],
  'Ethiopia': [9.145, 40.4897],
  'Tanzania': [-6.369, 34.8888],
  'Uganda': [1.3733, 32.2903],
  'Ghana': [7.9465, -1.0232],
  'Ivory Coast': [7.54, -5.5471],
  "Côte d'Ivoire": [7.54, -5.5471],
  'Senegal': [14.4974, -14.4524],
  'Cameroon': [7.3697, 12.3547],
  'Zimbabwe': [-19.0154, 29.1549],
  'Zambia': [-13.1339, 27.8493],
  'Botswana': [-22.3285, 24.6849],
  'Namibia': [-22.9576, 18.4904],
  'Mozambique': [-18.6657, 35.5296],
  'Madagascar': [-18.7669, 46.8691],
  'Angola': [-11.2027, 17.8739],
  'Democratic Republic of the Congo': [-4.0383, 21.7587],
  'Congo': [-0.228, 15.8277],
  'Cuba': [21.5218, -77.7812],
  'Dominican Republic': [18.7357, -70.1627],
  'Jamaica': [18.1096, -77.2975],
  'Puerto Rico': [18.2208, -66.5901],
  'Costa Rica': [9.7489, -83.7534],
  'Panama': [8.538, -80.7821],
  'Guatemala': [15.7835, -90.2308],
  'Honduras': [15.2, -86.2419],
  'El Salvador': [13.7942, -88.8965],
  'Nicaragua': [12.8654, -85.2072],
  'Paraguay': [-23.4425, -58.4438],
  'Uruguay': [-32.5228, -55.7658],
  'Bolivia': [-16.2902, -63.5887],
  'Bolivia, Plurinational State of': [-16.2902, -63.5887],
  'Iraq': [33.2232, 43.6793],
  'Syria': [34.8021, 38.9968],
  'Syrian Arab Republic': [34.8021, 38.9968],
  'Jordan': [30.5852, 36.2384],
  'Lebanon': [33.8547, 35.8623],
  'Kuwait': [29.3117, 47.4818],
  'Bahrain': [25.9304, 50.6378],
  'Qatar': [25.3548, 51.1839],
  'Oman': [21.4735, 55.9754],
  'Yemen': [15.5527, 48.5164],
  'Afghanistan': [33.9391, 67.71],
};

// Normalize country names to handle variations
export const normalizeCountryName = (name: string): string => {
  // Return as-is if it's in our dictionary
  if (COUNTRY_COORDS[name]) return name;
  
  // Try some common transformations
  const normalized = name.trim();
  
  // Check if any key matches case-insensitively
  for (const key of Object.keys(COUNTRY_COORDS)) {
    if (key.toLowerCase() === normalized.toLowerCase()) return key;
  }
  
  return normalized;
};

// Heat map color scale
export const getHeatColor = (intensity: number): string => {
  if (intensity < 0.1) return '#1a472a';
  if (intensity < 0.2) return '#2d5a3d';
  if (intensity < 0.3) return '#4a7c59';
  if (intensity < 0.4) return '#7eb77f';
  if (intensity < 0.5) return '#b4cf66';
  if (intensity < 0.6) return '#f9dc5c';
  if (intensity < 0.7) return '#f4a259';
  if (intensity < 0.8) return '#f25c54';
  if (intensity < 0.9) return '#e63946';
  return '#9d0208';
};




