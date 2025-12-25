import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './context/AuthContext';
import Layout from './components/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import AttackMap from './pages/AttackMap';
import Cowrie from './pages/Cowrie';
import Dionaea from './pages/Dionaea';
import Galah from './pages/Galah';
import RDPY from './pages/RDPY';
import Heralding from './pages/Heralding';
import Firewall from './pages/Firewall';
import Analytics from './pages/Analytics';
import Attackers from './pages/Attackers';
import LoadingSpinner from './components/LoadingSpinner';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-bg-primary flex items-center justify-center">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="attack-map" element={<AttackMap />} />
        <Route path="analytics" element={<Analytics />} />
        <Route path="cowrie" element={<Cowrie />} />
        <Route path="dionaea" element={<Dionaea />} />
        <Route path="galah" element={<Galah />} />
        <Route path="rdpy" element={<RDPY />} />
        <Route path="heralding" element={<Heralding />} />
        <Route path="firewall" element={<Firewall />} />
        <Route path="attackers" element={<Attackers />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default App;

