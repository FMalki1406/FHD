import { startLab } from './server.mjs';

const port = process.env.FHD_LAB_PORT === undefined ? 0 : Number(process.env.FHD_LAB_PORT);
const lab = await startLab({ port });
console.log(`HTTP fault lab: ${lab.url}/file`);
console.log('Local synthetic fixtures only. Ctrl+C stops the lab.');
let stopping = false;
const stop = async () => {
  if (stopping) return;
  stopping = true;
  await lab.close();
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
