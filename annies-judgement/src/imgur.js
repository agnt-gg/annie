import axios from 'axios';

export async function uploadToImgur(base64Image) {
  try {
    const response = await axios.post('https://api.imgur.com/3/image', {
      image: base64Image.split(',')[1], // Remove the data:image/png;base64, part
      type: 'base64'
    }, {
      headers: {
        'Authorization': `Client-ID ${process.env.IMGUR_CLIENT_ID}`
      }
    });
    
    return response.data.data.link;
  } catch (error) {
    console.error('Imgur upload error:', error);
    throw new Error('Failed to upload image');
  }
}