import { IncomingForm } from 'formidable';
import path from 'path';
import fs from 'fs/promises';
import { exec } from 'child_process';
import util from 'util';

const execPromise = util.promisify(exec);

export const config = {
  api: {
    bodyParser: false,
  },
};

export default async function handler(req, res) {
  if (req.method === 'POST') {
    const form = new IncomingForm({
      uploadDir: path.join(process.cwd(), 'uploads'),
      keepExtensions: true,
    });

    form.parse(req, async (err, fields, files) => {
      if (err) {
        console.error('Error', err);
        return res.status(500).json({ error: 'Error uploading file' });
      }

      const file = files.file?.[0];
      if (!file) {
        return res.status(400).json({ error: 'No file uploaded' });
      }

      const filePath = file.filepath;
      const fileName = file.originalFilename;

      try {
        const pythonPath = 'python'; // or 'python3' if you're using Python 3
        const scriptPath = path.join(process.cwd(), 'o1.py');
        const command = `${pythonPath} "${scriptPath}" "${filePath}"`;
        
        const { stdout, stderr } = await execPromise(command);
        
        if (stderr) {
          console.error('Python script error:', stderr);
          return res.status(500).json({ error: 'Error processing file: ' + stderr });
        }

        let result;
        try {
          const jsonStartIndex = stdout.lastIndexOf('{"result":');
          if (jsonStartIndex === -1) {
            throw new Error('No JSON result found in output');
          }
          const jsonString = stdout.slice(jsonStartIndex);
          result = JSON.parse(jsonString);
        } catch (parseError) {
          console.error('Error parsing Python script output:', parseError);
          console.error('Raw output:', stdout);
          return res.status(500).json({ error: 'Error parsing analysis result', rawOutput: stdout });
        }

        if (result.error) {
          return res.status(500).json({ error: result.error });
        }

        return res.status(200).json({ message: 'File analyzed successfully', result: result.result });
      } catch (error) {
        console.error('Error processing file:', error);
        return res.status(500).json({ error: 'Error processing file: ' + error.message });
      }
    });
  } else {
    res.setHeader('Allow', ['POST']);
    return res.status(405).end(`Method ${req.method} Not Allowed`);
  }
}