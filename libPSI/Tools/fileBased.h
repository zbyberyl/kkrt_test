#pragma once

#include <fstream>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <string>
//add
#include <sstream>

#include <vector>
#include <assert.h>

#include "libPSI/MPSI/Rr17/Rr17a/Rr17aMPsiReceiver.h"
#include "libPSI/MPSI/Rr17/Rr17a/Rr17aMPsiSender.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"

#include "libPSI/PSI/Kkrt/KkrtPsiReceiver.h"
#include "libPSI/PSI/Kkrt/KkrtPsiSender.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

#include "libPSI/PSI/ECDH/EcdhPsiReceiver.h"
#include "libPSI/PSI/ECDH/EcdhPsiSender.h"

#include "libPSI/MPSI/DKT/DktMPsiReceiver.h"
#include "libPSI/MPSI/DKT/DktMPsiSender.h"


namespace osuCrypto
{


	std::ifstream::pos_type filesize(std::ifstream& file);

	bool hasSuffix(std::string const& value, std::string const& ending);

	bool isHexBlock(const std::string& buff);
	block hexToBlock(const std::string& buff);

	enum class FileType
	{
		Bin,
		Csv,
		Unspecified
	};

	enum class Role {
		Sender = 0,
		Receiver = 1,
		Invalid
	};

	std::vector<block> readSet(const std::string& path, FileType ft, bool debug);
    std::vector<block> readSet(const std::string& path);

	void writeOutput(std::string outPath, FileType ft, const std::vector<u64>& intersection);
    void writeOutput(std::string outPath, const std::vector<std::vector<u64>>& intersection);


	void padSmallSet(std::vector<block>& set, u64& theirSize, const CLP& cmd);

	void doFilePSI(const CLP& cmd);
    void kkrtPSI(const CLP& cmd);
    void BucketByGetLine(const std::string &data, 
						const u32 &bucketNum, 
						std::vector<std::vector<block>> &vecData);
    void BucketByFile(const u32 &bucketNum,
                      const std::string &path,
                      std::vector<std::vector<std::string>> &vecData,
                      const SessionMode &epType);

    void PSIReceiverOrSender(const EpMode &epType,
                             const u32 &bucketNum,
                             std::vector<std::vector<std::string>> &vecData,
                             Endpoint &localEp,
                             Channel &localChannel,
                             std::vector<Channel> &vecChannels,
                             const u64 &statSetParam,
                             std::vector<std::vector<u64>> &vecIntersection);
    void RunPsiSender(const u64 &senderSize,
                      const u64 &receiverSize,
                      const std::vector<std::string> &vecSendData,
                      Channel &nthChannel,
                      const u64 &statSetParam);
    void RunPsiReceiver(const u64 &senderSize,
                        const u64 &receiverSize,
                        const std::vector<std::string> &vecSendData,
                        Channel &nthChannel,
                        const u64 &statSetParam,
                        std::vector<u64> &vecIntersection);

	block ItemToBlock(const std::string &dataItem);
	void printTime(std::string tag,
            std::vector<osuCrypto::Channel> chls,
            long long offlineTime, long long onlineTime,
            const osuCrypto::u64 &setSize,
            const osuCrypto::u64 &numThreads);
	

}

