import AttackStats from '../components/AttackStats/page';
import ModelControl from '../components/ModelControl/page';

export default function DashboardPage() {
  return (
    <div className="bg-black flex justify-center items-center h-screen px-4 py-6 sm:px-6 lg:px-10">
      <div className="flex flex-col md:flex-row gap-6">
        <AttackStats />
        <ModelControl />
      </div>
    </div>
  );
}