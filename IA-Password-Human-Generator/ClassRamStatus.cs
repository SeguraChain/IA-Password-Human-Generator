
using System.Diagnostics;
using System.Threading.Tasks;


namespace IA_Mot_De_Passe_Humain_Projet
{
    public class ClassRamStatus
    {
        private const long RamLimitInMb = 8192;
        private static PerformanceCounter _ramCounter = new PerformanceCounter("Memory", "Available MBytes", true);
        private static float _availbleRam;

        public static void EnableRamCounterTask()
        {
            Task.Factory.StartNew(async () =>
            {
                while(true)
                {
                    _availbleRam = _ramCounter.NextValue();
                    await Task.Delay(1000);
                }
            }).ConfigureAwait(false);
        }

        public static bool RamAvailableStatus()
        {
            if (_availbleRam > RamLimitInMb)
            {
                return true;
            }
            return false;
        }
    }
}
