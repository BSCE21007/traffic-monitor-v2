import LogsTable from '../components/LogsTable/page';

export default function LogsPage() {
  return (
    <div className=" space-y-4 text-white">
      <h1 className="text-3xl mt-10 text-center font-semibold">ATTACK LOGS</h1>
      <LogsTable />
    </div>
  );
}
