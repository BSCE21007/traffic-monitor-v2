import axios from 'axios';

export async function runModel(type: 'rf' | 'rl') {
  const res = await axios.get(`http://localhost:5000/api/run_${type}`);
  return res.data;
}

export async function fetchLogs(): Promise<string[]> {
  const res = await axios.get('http://localhost:5000/api/logs');
  return res.data.logs;
}
