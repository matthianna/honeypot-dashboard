import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './context/AuthContext';
import Layout from './components/Layout';
import ErrorBoundary from './components/ErrorBoundary';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import AttackMap from './pages/AttackMap';
import FirewallMap from './pages/FirewallMap';
import Cowrie from './pages/Cowrie';
import CowrieDemo from './pages/CowrieDemo';
import Dionaea from './pages/Dionaea';
import Galah from './pages/Galah';
import GalahAttackers from './pages/GalahAttackers';
import RDPY from './pages/RDPY';
import Heralding from './pages/Heralding';
import Firewall from './pages/Firewall';
import Attackers from './pages/Attackers';
import Mitre from './pages/Mitre';
import GlobalMap from './pages/GlobalMap';
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
    <ErrorBoundary>
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
          <Route index element={<ErrorBoundary><Dashboard /></ErrorBoundary>} />
          <Route path="attack-map" element={<ErrorBoundary><AttackMap /></ErrorBoundary>} />
          <Route path="firewall-map" element={<ErrorBoundary><FirewallMap /></ErrorBoundary>} />
          <Route path="cowrie" element={<ErrorBoundary><Cowrie /></ErrorBoundary>} />
          <Route path="cowrie-demo" element={<ErrorBoundary><CowrieDemo /></ErrorBoundary>} />
          <Route path="dionaea" element={<ErrorBoundary><Dionaea /></ErrorBoundary>} />
          <Route path="galah" element={<ErrorBoundary><Galah /></ErrorBoundary>} />
          <Route path="galah/attackers" element={<ErrorBoundary><GalahAttackers /></ErrorBoundary>} />
          <Route path="rdpy" element={<ErrorBoundary><RDPY /></ErrorBoundary>} />
          <Route path="heralding" element={<ErrorBoundary><Heralding /></ErrorBoundary>} />
          <Route path="firewall" element={<ErrorBoundary><Firewall /></ErrorBoundary>} />
          <Route path="attackers" element={<ErrorBoundary><Attackers /></ErrorBoundary>} />
          <Route path="mitre" element={<ErrorBoundary><Mitre /></ErrorBoundary>} />
          <Route path="global-map" element={<ErrorBoundary><GlobalMap /></ErrorBoundary>} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </ErrorBoundary>
  );
}

export default App;

