#include <iomanip>

#include "fileBased.h"




namespace osuCrypto
{

    template<typename ... Args>
    std::string string_format(const std::string& format, Args ... args)
    {
        size_t size = std::snprintf(nullptr, 0, format.c_str(), args ...) + 1; // Extra space for '\0'
        std::unique_ptr<char[]> buf(new char[size]);
        std::snprintf(buf.get(), size, format.c_str(), args ...);
        return std::string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
    }


    void printTime(
            std::string tag,
            std::vector<osuCrypto::Channel> chls,
            long long offlineTime, long long onlineTime,

            const osuCrypto::u64 &setSize,
            const osuCrypto::u64 &numThreads

    )
    {
        u64 dataSent = 0, dataRecv(0);
        for (u64 g = 0; g < chls.size(); ++g)
        {
            dataSent += chls[g].getTotalDataSent();
            dataRecv += chls[g].getTotalDataRecv();
            chls[g].resetStats();

            /*
            if (chls2)
            {
                dataSent += (*chls2)[g].getTotalDataSent();
                dataRecv += (*chls2)[g].getTotalDataRecv();
                (*chls2)[g].resetStats();
            }
             */

        }

        // mico seconds
        double time = 1.0 * offlineTime + onlineTime;

        // milliseconds
        time /= 1000;
        auto Mbps = dataSent * 8 / time / (1 << 20);
        auto MbpsRecv = dataRecv * 8 / time / (1 << 20);

        //if (params.mVerbose)
        {
            std::cout << std::setw(6) << tag << " n = " << setSize << "  threads = " << numThreads << "\n"
                      << "      Total Time = " << time << " s\n"
                      << "         Total = " << offlineTime << " ms\n"
                      << "          Online = " << onlineTime << " ms\n"
                      << "      Total Comm = " << string_format("%5.2f", (dataRecv + dataSent) / std::pow(2.0, 20)) << " MB\n"
                      //<< "      Total Comm = " << string_format("%4.2f", dataSent / std::pow(2.0, 20)) << ", " << string_format("%4.2f", dataRecv / std::pow(2.0, 20)) << " MB\n"
                      << "       Bandwidth = " << string_format("%4.2f", Mbps) << ", " << string_format("%4.2f", MbpsRecv) << " Mbps\n" << std::endl;


            /*
            if (params.mVerbose > 1)
                std::cout << gTimer << std::endl;
                */
        }
        /*
        else
        {
            std::cout << std::dec << std::setw(6) << tag
                      << std::setw(8) << (std::to_string(setSize) + (n2 == u64(-1)? "" : "vs"+std::to_string(n2)))
                      << std::setw(10) << (std::to_string(numThreads) + " " + std::to_string(s))
                      << std::setw(14) << (offlineTime + onlineTime)
                      << std::setw(14) << onlineTime
                      << std::setw(18) << (string_format("%4.2f", (dataRecv + dataSent) / std::pow(2.0, 20)))
                      //<< std::setw(18) << (string_format("%4.2f", dataSent / std::pow(2.0, 20)) + ", " + string_format("%4.2f", dataRecv / std::pow(2.0, 20)))
                      << std::setw(18) << (string_format("%4.2f", Mbps) + ", " + string_format("%4.2f", MbpsRecv)) << std::endl;
        }
         */
    }


	std::ifstream::pos_type filesize(std::ifstream& file)
	{
		auto pos = file.tellg();
		file.seekg(0, std::ios_base::end);
		auto size = file.tellg();
		file.seekg(pos, std::ios_base::beg);
		return size;
	}



	bool hasSuffix(std::string const& value, std::string const& ending)
	{
		if (ending.size() > value.size()) return false;
		return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
	}

	bool isHexBlock(const std::string& buff)
	{
		if (buff.size() != 32)
			return false;
		auto ret = true;
		for (u64 i = 0; i < 32; ++i)
			ret &= (bool)std::isxdigit(buff[i]);
		return ret;
	}

	block hexToBlock(const std::string& buff)
	{
		assert(buff.size() == 32);

		std::array<u8, 16> vv;
		char b[3];
		b[2] = 0;

		for (u64 i = 0; i < 16; ++i)
		{
			b[0] = buff[2 * i + 0];
			b[1] = buff[2 * i + 1];
			vv[15 - i] = (char)strtol(b, nullptr, 16);;
		}
		return toBlock(vv.data());
	}

	std::vector<block> readSet(const std::string& path, FileType ft, bool debug)
	{
		std::vector<block> ret;
		if (ft == FileType::Bin)
		{
			std::ifstream file(path, std::ios::binary | std::ios::in);
			if (file.is_open() == false)
				throw std::runtime_error("failed to open file: " + path);
			auto size = filesize(file);
			if (size % 16)
				throw std::runtime_error("Bad file size. Expecting a binary file with 16 byte elements");

			ret.resize(size / 16);
			file.read((char*)ret.data(), size);
		}
		else if (ft == FileType::Csv)
		{
			// we will use this to hash large inputs
			RandomOracle hash(sizeof(block));

			std::ifstream file(path, std::ios::in);
			if (file.is_open() == false)
				throw std::runtime_error("failed to open file: " + path);
			std::string buffer;
			while (std::getline(file, buffer))
			{
				// if the input is already a 32 char hex 
				// value, just parse it as is.
				if (isHexBlock(buffer))
				{
					ret.push_back(hexToBlock(buffer));
				}
				else
				{
					ret.emplace_back();
					hash.Reset();
					hash.Update(buffer.data(), buffer.size());
					hash.Final(ret.back());
				}
			}
		}
		else
		{
			throw std::runtime_error("unknown file type");
		}

		if (debug)
		{
			u64 maxPrint = 40;
			std::unordered_map<block, u64> hashes;
			for (u64 i = 0; i < ret.size(); ++i)
			{
				auto r = hashes.insert({ ret[i], i });
				if (r.second == false)
				{
					std::cout << "duplicate at index " << i << " & " << r.first->second << std::endl;
					--maxPrint;

					if (!maxPrint)
						break;
				}
			}


			if (maxPrint != 40)
				throw RTE_LOC;
		}

		return ret;
	}


    std::vector<block> readSet(const std::string& path)
    {
        std::vector<block> ret;

        // we will use this to hash large inputs
        RandomOracle hash(sizeof(block));

        std::ifstream file(path, std::ios::in);
        if (file.is_open() == false)
            throw std::runtime_error("failed to open file: " + path);
        std::string buffer;
        while (std::getline(file, buffer))
        {
                // if the input is already a 32 char hex
                // value, just parse it as is.
                if (isHexBlock(buffer))
                {
                    ret.push_back(hexToBlock(buffer));
                }
                else
                {
                    ret.emplace_back();
                    hash.Reset();
                    hash.Update(buffer.data(), buffer.size());
                    hash.Final(ret.back());
                }
            }
        return ret;
    }

	void writeOutput(std::string outPath, FileType ft, const std::vector<u64>& intersection)
	{
		std::ofstream file;

		if (ft == FileType::Bin)
			file.open(outPath, std::ios::out | std::ios::trunc | std::ios::binary);
		else
			file.open(outPath, std::ios::out | std::ios::trunc);

		if (file.is_open() == false)
			throw std::runtime_error("failed to open the output file: " + outPath);

		if (ft == FileType::Bin)
		{
			file.write((char*)intersection.data(), intersection.size() * sizeof(u64));
		}
		else
		{
			for (auto i : intersection)
				file << i << "\n";
		}
	}

	void writeOutput(std::string outPath, const std::vector<std::vector<u64>>& intersection)
	{
		std::ofstream file;
		file.open(outPath, std::ios::out | std::ios::trunc);

		if (file.is_open() == false)
			throw std::runtime_error("failed to open the output file: " + outPath);
        for (auto i = 0; i < intersection.size(); ++i) {
            for (auto j : intersection[i])
            { file << j << "\n"; }
        }

		
	}

	void padSmallSet(std::vector<block>& set, u64& theirSize, const CLP& cmd)
	{
		if (set.size() != theirSize)
		{
			if (cmd.isSet("padSmallSet") == false)
				throw std::runtime_error("This protocol currently requires equal set sizes. Use the -padSmallSet flag to add padding to the smaller set. Note that a malicious party can now have a larger set. If this is an problem feel free to open a github issue. ");

			if (set.size() < theirSize)
			{
				set.reserve(theirSize);
				PRNG prng(sysRandomSeed());
				while (set.size() != theirSize)
					set.push_back(prng.get<block>());
			}
			else
				theirSize = set.size();
		}
	}

    /**
     * @description: 将文件每行分桶放入vecData
     * @param {string} &data 文件路径
     * @param {u32} &bucketNum 分桶数
     * @param {	vector	} vecData 分桶，存放string类型
     * @return {*}
     */
    void BucketByGetLine(const std::string &data, 
						const u32 &bucketNum, 
						std::vector<std::vector<std::string>> &vecData)
    {
        u64 n = 0;
//        std::cout << "-----------in BucketByGetLine-------------" << std::endl;
        std::ifstream dataFile(data, std::ios::in);
        if (dataFile.is_open() == false)
            throw std::runtime_error("failed to open file: " + data);
//        std::cout << "-----------in BucketByGetLine----1---------" << std::endl;
        std::string dataItem;//存放每行输入
        std::hash<std::string> hashStr;

//        std::cout << "-----------in BucketByGetLine-----2--------" << std::endl;
        while(std::getline(dataFile, dataItem))
        {
//            std::cout << "dataItem = " << dataItem << std::endl;
            n++;
            auto k = hashStr(dataItem) % (bucketNum);
//            std::cout << "k = " << k << std::endl;
            vecData[k].emplace_back(dataItem);//放入对应桶中
//            std::cout << "-----------vecData["<< k <<"]input "<< dataItem <<"-------------" << std::endl;
        }
        std::cout << "n = " << n << std::endl;
    }
	
	block ItemToBlock(const std::string &dataItem)
	{
		std::hash<std::string> hash_str;
		u64 tmpDataItem = (u64)hash_str(dataItem);
		return toBlock(tmpDataItem);

	}


    /**
     * @description: 将文件分桶到vecData
     * @param {u32} &bucketNum 分桶数
     * @param {string} &path 输入文件路径
     * @param {	vector	} vecData 分桶
     * @param {SessionMode} &epType 模式
     * @return {*}
     */
    void BucketByFile(const u32 &bucketNum, 
					const std::string &path, 
					std::vector<std::vector<std::string>> &vecData,
					const SessionMode &epType)
    {
//        std::cout << "-----------in BucketByFile-------------" << std::endl;
        std::hash<std::string> hashStr;
        std::ifstream localIfFile(path, std::ios::in);
        if (localIfFile.is_open() == false)
            throw std::runtime_error("failed to open file: " + path);
//        std::cout << "-----------in BucketByFile--1-----------" << std::endl;
        BucketByGetLine(path, bucketNum, vecData);

        for (auto i = 0; i < bucketNum; ++i)
        {
            if(vecData[i].empty())//空桶补dummy元素
            {
                std::string strValue;
                //r = 0 :client && sender
                //r = 1 :server && receiver
                if(epType == SessionMode::Server)
                {
					strValue = "server dummy item";
                    std::cout<< "The receiver bucket [" << i<< "] is empty\n";
                }
                else
                {
					strValue = "client dummy item";
                    std::cout<< "The sender bucket [" << i<< "] is empty\n";
                }
                vecData[hashStr(strValue) % bucketNum].emplace_back(strValue);
            }

        }

    }


 /**
  * @description: 根据分桶数起线程分别执行PSI，结果统一放至vecIntersection
  * @param {EpMode} &epType 模式
  * @param {u32} &bucketNum 分桶数
  * @param {vector	} vecData 各分桶
  * @param {Endpoint} &localEp 长连接
  * @param {Channel} &localChannel 传递size的channel
  * @param {vector		} vecChannels 放置各个线程建立的channel的容器
  * @param {u64} statSetParam 统计安全参数
  * @param {vector<u64>} &vecIntersection 交集结果
  * @return {*}
  */
	void PSIReceiverOrSender(const EpMode &epType, 
							const u32 &bucketNum, 
							std::vector<std::vector<std::string>> &vecData,
							Endpoint &localEp,
							Channel &localChannel,
							std::vector<Channel> &vecChannels,
							const u64 &statSetParam,
							std::vector<std::vector<u64>> &vecIntersection)
	{
        //std::cout << "vecData.size:" << vecData.size() << std::endl;
		std::vector<u64> vecSenderSize(bucketNum );//sender 各桶元素数
		std::vector<u64> vecReceiverSize(bucketNum ) ;//receiver 各桶元素数
		std::vector<u64> vecDataSize(bucketNum );//本方各桶元素数

		std::vector<std::thread> vecThreads(bucketNum);//每分桶一个线程
		for (int i = 0; i < bucketNum; i++)
		{
			/* code */
			vecDataSize[i] = (u64)vecData[i].size();
		}
		if(epType == EpMode::Client)
		{//r = 0 :client && sender
			if(localChannel.isConnected())
			{
				std::cout << "client channel is connected " << std::endl;
			}
			else
			{
				std::cout << "client channel is not connected " << std::endl;

			}
			for (auto i = 0; i < bucketNum; i++)
			{
				/* code */
				localChannel.asyncSend(vecDataSize[i]);
			}

			for (auto i = 0; i < bucketNum; i++)
			{
				/* code */
				localChannel.recv(vecReceiverSize[i]);
			}
			for (auto i = 0; i < bucketNum; i++)
			{
				/* code */
				vecChannels[i] = localEp.addChannel(std::to_string(i + 1), std::to_string(i + 1));

			}

			for (u32 i = 0; i < bucketNum; i++)
			{
				/* code */
				if(vecChannels[i].isConnected())
				{
					std::cout << "client channel "<< i + 1 <<" is connected " << std::endl;
					
				}
				else
				{
					std::cout << "client channel "<< i + 1 <<" is not connected " << std::endl;

				}

                //std::cout << "------------\n";

				vecThreads[i] = std::thread(RunPsiSender, 
											vecDataSize[i],
											std::ref(vecReceiverSize[i]),
											std::ref(vecData[i]),
											std::ref(vecChannels[i]),
											std::ref(statSetParam));
                //std::cout << "bucket[" << i << "] is done\n";

			}

            //std::cout << "client" << std::endl;
            for (int i = 0; i < bucketNum; ++i) {
                vecThreads[i].join();

            }
			
		}
		else
		{//EpMode::Server
			if(localChannel.isConnected())
			{
				std::cout << "server channel is connected " << std::endl;
			}
			else
			{
				std::cout << "server channel is not connected " << std::endl;

			}
			for (auto i = 0; i < bucketNum; i++)
			{
				/* code */
				localChannel.asyncSend(vecDataSize[i]);
			}
			for (auto i = 0; i < bucketNum; i++)
			{
				/* code */
				localChannel.recv(vecSenderSize[i]);
			}
			for (auto i = 0; i < bucketNum; i++)
			{
				/* code */
				vecChannels[i] = localEp.addChannel(std::to_string(i + 1), std::to_string(i + 1));

			}
			for (u32 i = 0; i < bucketNum; i++)
			{
				/* code */
				if(vecChannels[i].isConnected())
				{
					std::cout << "server channel "<< i + 1 <<" is connected " << std::endl;
					
				}
				else
				{
					std::cout << "server channel "<< i + 1 <<" is not connected " << std::endl;

				}

				vecThreads[i] = std::thread(RunPsiReceiver,
				                            std::ref(vecSenderSize[i]),
											vecDataSize[i],
											std::ref(vecData[i]),
											std::ref(vecChannels[i]),
											std::ref(statSetParam),
											std::ref(vecIntersection[i]));


			}
            //std::cout << "Server" << std::endl;
            for (int i = 0; i < bucketNum; ++i) {
                vecThreads[i].join();

            }
		}
		
	}


 /**
  * @description: sender每次具体执行流程
  * @param {u64} &senderSize 
  * @param {u64} &receiverSize
  * @param {vector<std::string>} &vecSendData 本方每次psi的输入数据，类型为string
  * @param {Channel} &nthChannel 对应的channel
  * @param {u64} statSetParam 统计安全参数
  * @return {*}
  */
	void RunPsiSender(const u64 &senderSize,
					const u64 &receiverSize,
					const std::vector<std::string> &vecSendData,
					Channel &nthChannel,
					const u64 &statSetParam)
	{
			// KkrtNcoOtSender ot;
			// 		KkrtPsiSender sender;

            //          Timer timer;
            //         auto start = timer.setTimePoint("start");

			// 		//sender.init(set.size(), theirSize, statSetParam, chl, ot, sysRandomSeed());
			// 		auto mid = timer.setTimePoint("init");
            //         //sender.sendInput(set, chl);

            //         auto end = timer.setTimePoint("done");

            //          auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - readfile).count();
            //          auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();
            //          //printHeader();

            //          //-------
            //         // printTime("kkrt", ChlsParam, offlineTime, onlineTime, set.size(), 1);
		std::vector<block> vecBlockData;//将每个桶中元素转化为block类型
		for (auto i = 0; i < vecSendData.size(); i++)
		{
			/* code */
			vecBlockData.emplace_back(ItemToBlock(vecSendData[i]));
		}		
		KkrtNcoOtSender ot;
		KkrtPsiSender sender;
		sender.init(senderSize, receiverSize, statSetParam, nthChannel, ot, sysRandomSeed());
		sender.sendInput(vecBlockData, nthChannel);
        std::cout << "sender is done\n";

	}

 /**
  * @description: receiver每次具体执行流程
  * @param {u64} &senderSize
  * @param {u64} &receiverSize
  * @param {vector<std::string>} &vecSendData 本方每次psi的输入数据，类型为string
  * @param {Channel} &nthChannel 对应的channel
  * @param {u64} statSetParam 统计安全参数
  * @param {vector<u64>} &vecIntersection 交集输出
  * @return {*}
  */
	void RunPsiReceiver(const u64 &senderSize,
					const u64 &receiverSize,
					const std::vector<std::string> &vecSendData,
					Channel &nthChannel,
					const u64 &statSetParam,
					std::vector<u64> &eachIntersection)
	{
		std::vector<block> vecBlockData;//将每个桶中元素转化为block类型
		for (auto i = 0; i < vecSendData.size(); i++)
		{
			/* code */
			vecBlockData.emplace_back(ItemToBlock(vecSendData[i]));
		}
		
		KkrtNcoOtReceiver ot;
		KkrtPsiReceiver recver;
		recver.init(senderSize, receiverSize, statSetParam, nthChannel, ot, sysRandomSeed());
		recver.sendInput(vecBlockData, nthChannel);
		u64 tempu64;
        std::stringstream ss;
                    
		for (auto i : recver.mIntersection)//recver.mintersection存放每次交集对应的输入数据的顺序
        {                     
			ss << vecSendData[i];
            ss >> tempu64;       
			eachIntersection.emplace_back(tempu64);
        }
        std::cout << "recver is done\n";
	}



    void kkrtPSI(const CLP& cmd)
    {
        try {
            Timer timer;
            auto start = timer.setTimePoint("start");

            auto path = cmd.get<std::string>("in");//输入文件路径
            //std::cout << "path " << path << std::endl;
            auto outPath = cmd.getOr<std::string>("out", path + ".out");//输出文件路径


            // std::cout << "readfile" << std::endl;
            // auto readfile = wholeTimer.setTimePoint("readfile");

            // std::vector <block> set = readSet(path);

            u64 statSetParam = cmd.getOr("ssp", 40);//统计安全参数
            auto ip = cmd.getOr<std::string>("ip", "localhost:1212");//server ip
            auto bucketNum = cmd.getOr<int>("bucket", 1);//分桶数
            std::vector<std::vector<std::string>> vecData(bucketNum);//数据分桶，每个桶存放数据的string形式
            std::vector<std::vector<u64>> vecIntersection(bucketNum);//交集结果
            auto r = (Role) cmd.getOr<int>("r", 2);//角色 0：sender/client 1：receiver/server
            if (r != Role::Sender && r != Role::Receiver)
                throw std::runtime_error("-r tag must be set with value 0 (sender) or 1 (receiver).");

            //auto isServer = cmd.getOr<int>("server", (int) r);
            // if (r != Role::Sender && r != Role::Receiver)
            //     throw std::runtime_error("-server tag must be set with value 0 or 1.");

            //auto mode = isServer ? SessionMode::Server : SessionMode::Client;
            //std::cout << "-----------in kkrtPSI-------1-------" << std::endl;
//#if defined(ENABLE_KKRT) && defined(ENABLE_KKRT_PSI)
           // std::cout << "-----------in kkrtPSI-------1.5-------" << std::endl;
			std::string strExchangeSize = "exchangeSize";
           /* Session ses(ios, ip, mode, "");
            Channel chl = ses.addChannel();

            std::vector <Channel> ChlsParam;
            ChlsParam.push_back(chl);

            if (!chl.waitForConnection(std::chrono::milliseconds(1000))) {
                std::cout << "waiting for connection" << std::flush;
                while (!chl.waitForConnection(std::chrono::milliseconds(1000)))
                    std::cout << "." << std::flush;
                std::cout << " done" << std::endl;
            }

            if (set.size() != cmd.getOr((r == Role::Sender) ? "senderSize" : "receiverSize", set.size()))
                throw std::runtime_error("File does not contain the specified set size.");

            u64 theirSize;
            chl.send(set.size());
            chl.recv(theirSize);
            if (theirSize != cmd.getOr((r != Role::Sender) ? "senderSize" : "receiverSize", theirSize))
                throw std::runtime_error("Other party's set size does not match.");
*/

            if (r == Role::Sender)
				{//r = 0 :client && sender
                
					IOService ios;
					std::string str_main_chlname = "main_channel";
    				std::string str_close_chlname = "close_channel";
					BucketByFile(bucketNum, path, vecData, SessionMode::Client);
                    //std::cout << "-----------in kkrtPSI-------1.6-------" << std::endl;
					auto afterBucket = timer.setTimePoint("afterBucket");
                    Endpoint localEp(ios, ip, EpMode::Client, strExchangeSize);
					Channel localChannel = localEp.addChannel(str_main_chlname, str_main_chlname);
					Channel localCloseChannel = localEp.addChannel(str_close_chlname, str_close_chlname);
					std::vector<Channel> vecChannels(bucketNum);
                    //std::cout << "-----------in kkrtPSI-------2-------" << std::endl;
					PSIReceiverOrSender(EpMode::Client, 
							bucketNum, 
							vecData,
							localEp,
							localChannel,
							vecChannels,
							statSetParam,
							vecIntersection);

					u64 u_close;
                    u64 dataSent = 0, dataRecv = 0;
					localCloseChannel.recv(u_close);
					for (auto i = 0; i < bucketNum; i++)
					{
                        dataSent += vecChannels[i].getTotalDataSent();
                        dataRecv += vecChannels[i].getTotalDataRecv();
						vecChannels[i].close();
					}
					localCloseChannel.close();
					localChannel.close();
					localEp.stop();
					ios.stop();

                    std::cout << "done\n";
                    auto end = timer.setTimePoint("end");

                    auto totalTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                    auto bucketTime = std::chrono::duration_cast<std::chrono::milliseconds>(afterBucket - start).count();
                    std::cout << "11111111111111\n";
                    std::cout << "Total Time is " << totalTime << " ms\n";
                    std::cout << "bucket Time is " << bucketTime<< " ms\n";

                    std::cout << " Total Comm = " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB\n";

                    std::cout << "end\n";
					// KkrtNcoOtSender ot;
					// KkrtPsiSender sender;


                    //  Timer timer;
                    // auto start = timer.setTimePoint("start");

					//sender.init(set.size(), theirSize, statSetParam, chl, ot, sysRandomSeed());
					// auto mid = timer.setTimePoint("init");
                    //sender.sendInput(set, chl);

                    // auto end = timer.setTimePoint("done");

                    //  auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - readfile).count();
                    //  auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();
                     //printHeader();

                     //-------
                    // printTime("kkrt", ChlsParam, offlineTime, onlineTime, set.size(), 1);
				}
				else
				{//r = 1 :server && receiver
					IOService ios;
					std::string str_main_chlname = "main_channel";
    				std::string str_close_chlname = "close_channel";
                    BucketByFile(bucketNum, path, vecData, SessionMode::Server);
                    //std::cout << "-----------in kkrtPSI-------1.6-------" << std::endl;
					auto afterBucket = timer.setTimePoint("afterBucket");
                    Endpoint localEp(ios, ip, EpMode::Server, strExchangeSize);
					Channel localChannel = localEp.addChannel(str_main_chlname, str_main_chlname);
					Channel localCloseChannel = localEp.addChannel(str_close_chlname, str_close_chlname);

					std::vector<Channel> vecChannels(bucketNum);
                    //std::cout << "-----------in kkrtPSI-------2-------" << std::endl;
					PSIReceiverOrSender(EpMode::Server, 
							bucketNum, 
							vecData,
							localEp,
							localChannel,
							vecChannels,
							statSetParam,
							vecIntersection);


					// KkrtNcoOtReceiver ot;
					// KkrtPsiReceiver recver;
					//recver.init(theirSize, set.size(), statSetParam, chl, ot, sysRandomSeed());
                    // auto offlineEnd = wholeTimer.setTimePoint("offlineEnd");
                    //recver.sendInput(set, chl);

                    //std::vector<u64> intersectionValue = recver.sendInput(set, chl, path, ft);

                    //CSV
                    // std::vector<u64> wholeFile;
                    // std::vector<u64> myResult;
                    // //path-original file
                    // std::ifstream orifp(path);
                    // std::string buffer;
			        // while (std::getline(orifp, buffer))
                    // {
                    //     u64 tempu64;
                    //     std::stringstream ss;
                    //     ss<<buffer;
                    //     ss>>tempu64;
				    //     wholeFile.push_back(tempu64);
			        // }
                    // for (auto i : vecIntersection)
                    // {                            
					// 	myResult.push_back(wholeFile[i]);
                    // }
                    writeOutput(outPath, vecIntersection);

					u64 u_close = 123;
                    u64 dataSent = 0, dataRecv = 0;
					localCloseChannel.send(u_close);
					for (auto i = 0; i < bucketNum; i++)
					{
                        dataSent += vecChannels[i].getTotalDataSent();
                        dataRecv += vecChannels[i].getTotalDataRecv();
						vecChannels[i].close();
					}

					localCloseChannel.close();
					localChannel.close();
					localEp.stop();
					ios.stop();

                    std::cout << "done\n";
                    auto end = timer.setTimePoint("end");

                    auto totalTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                    auto bucketTime = std::chrono::duration_cast<std::chrono::milliseconds>(afterBucket - start).count();

                    std::cout << "Total Time is " << totalTime << " ms\n";
                    std::cout << "bucket Time is " << bucketTime<< " ms\n";
                    std::cout << "Total Comm is " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB\n";


                    //writeOutput(outPath, ft, recver.realIntersection);
                    //from vector
                    //if csv xxxx[0..10] ->csv [0..10]
                    //if bin xxxx[0..10] ->func [0..10]
                    //writeOutput(outPath,ft,myvector)
                    // auto done = wholeTimer.setTimePoint("donePSI");
                    // auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(offlineEnd - readfile).count();
                    // auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(done - offlineEnd).count();
                     //printHeader();

                     //-------
                    //  printTime("kkrt", ChlsParam, offlineTime, onlineTime, set.size(), 1);
				}
//#else
//            throw std::runtime_error("ENABLE_KKRT_PSI not defined.");
//#endif

            }catch (std::exception& e)
            {
                std::cout << Color::Red << "Exception: " << e.what() << std::endl << Color::Default;

                std::cout << "Try adding command line argument -debug" << std::endl;
             }
    }


	void doFilePSI(const CLP& cmd)
	{
		try {
			auto path = cmd.get<std::string>("in");
			auto outPath = cmd.getOr<std::string>("out", path + ".out");
			bool debug = cmd.isSet("debug");

			FileType ft = FileType::Unspecified;
			if (cmd.isSet("bin")) ft = FileType::Bin;
			if (cmd.isSet("csv")) ft = FileType::Csv;
			if (ft == FileType::Unspecified)
			{
				if (hasSuffix(path, ".bin"))
					ft = FileType::Bin;
				else if (hasSuffix(path, ".csv"))
					ft = FileType::Csv;
			}
			if (ft == FileType::Unspecified)
				throw std::runtime_error("unknown file extension, must be .csv or .bin or you must specify the -bin or -csv flags.");

            Timer wholeTimer;
            std::cout << "readfile" << std::endl;
            auto readfile = wholeTimer.setTimePoint("readfile");

			std::vector<block> set = readSet(path, ft, debug);

			u64 statSetParam = cmd.getOr("ssp", 40);
			auto ip = cmd.getOr<std::string>("ip", "localhost:1212");
			auto r = (Role)cmd.getOr<int>("r", 2);
			if (r != Role::Sender && r != Role::Receiver)
				throw std::runtime_error("-r tag must be set with value 0 (sender) or 1 (receiver).");

			auto isServer = cmd.getOr<int>("server", (int)r);
			if (r != Role::Sender && r != Role::Receiver)
				throw std::runtime_error("-server tag must be set with value 0 or 1.");

			auto mode = isServer ? SessionMode::Server : SessionMode::Client;
			IOService ios;
			Session ses(ios, ip, mode, "");
			Channel chl = ses.addChannel();

            std::vector<Channel> ChlsParam;
            ChlsParam.push_back(chl);

			if (!chl.waitForConnection(std::chrono::milliseconds(1000)))
			{
				std::cout << "waiting for connection" << std::flush;
				while (!chl.waitForConnection(std::chrono::milliseconds(1000)))
					std::cout << "." << std::flush;
				std::cout << " done" << std::endl;
			}

			if (set.size() != cmd.getOr((r == Role::Sender) ? "senderSize" : "receiverSize", set.size()))
				throw std::runtime_error("File does not contain the specified set size.");

			u64 theirSize;
			chl.send(set.size());
			chl.recv(theirSize);
			if (theirSize != cmd.getOr((r != Role::Sender) ? "senderSize" : "receiverSize", theirSize))
				throw std::runtime_error("Other party's set size does not match.");


			if (cmd.isSet("kkrt"))
			{
#if defined(ENABLE_KKRT) && defined(ENABLE_KKRT_PSI)
				if (r == Role::Sender)
				{
					KkrtNcoOtSender ot;
					KkrtPsiSender sender;

                     Timer timer;
                    auto start = timer.setTimePoint("start");

					sender.init(set.size(), theirSize, statSetParam, chl, ot, sysRandomSeed());
					auto mid = timer.setTimePoint("init");
                    sender.sendInput(set, chl);

                    auto end = timer.setTimePoint("done");

                     auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - readfile).count();
                     auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();
                     //printHeader();

                     //-------
                     printTime("kkrt", ChlsParam, offlineTime, onlineTime, set.size(), 1);
				}
				else
				{

					KkrtNcoOtReceiver ot;
					KkrtPsiReceiver recver;
					recver.init(theirSize, set.size(), statSetParam, chl, ot, sysRandomSeed());
                    auto offlineEnd = wholeTimer.setTimePoint("offlineEnd");
                    recver.sendInput(set, chl);

                    //std::vector<u64> intersectionValue = recver.sendInput(set, chl, path, ft);

                    //CSV
                    if(ft==FileType::Bin){
                        writeOutput(outPath, ft, recver.mIntersection);
                    }
                    if(ft==FileType::Csv){
                        std::vector<u64> wholeFile;
                        std::vector<u64> myResult;
                        //path-original file
                        std::ifstream orifp(path);
                        std::string buffer;
			            while (std::getline(orifp, buffer))
                        {
                            u64 tempu64;
                            std::stringstream ss;
                            ss<<buffer;
                            ss>>tempu64;
					        wholeFile.push_back(tempu64);
				        }
                        for (auto i : recver.mIntersection)
                        {
                            myResult.push_back(wholeFile[i]);
                        }
                        writeOutput(outPath, ft, myResult);

                    }

                    //writeOutput(outPath, ft, recver.realIntersection);
                    //from vector
                    //if csv xxxx[0..10] ->csv [0..10]
                    //if bin xxxx[0..10] ->func [0..10]
                    //writeOutput(outPath,ft,myvector)
                    auto done = wholeTimer.setTimePoint("donePSI");
                    auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(offlineEnd - readfile).count();
                    auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(done - offlineEnd).count();
                     //printHeader();

                     //-------
                     printTime("kkrt", ChlsParam, offlineTime, onlineTime, set.size(), 1);
				}
#else 
				throw std::runtime_error("ENABLE_KKRT_PSI not defined.");
#endif
			}
			else if (cmd.isSet("rr17a"))
			{
#if defined(ENABLE_OOS) && defined(ENABLE_RR17_PSI)
				padSmallSet(set, theirSize, cmd);

				if (r == Role::Sender)
				{
					OosNcoOtSender ots;
					OosNcoOtReceiver otr;
					Rr17aMPsiSender sender;
					sender.init(set.size(), statSetParam, chl, ots, otr, sysRandomSeed());
					sender.sendInput(set, chl);
				}
				else
				{
					OosNcoOtSender ots;
					OosNcoOtReceiver otr;
					Rr17aMPsiReceiver recver;
					recver.init(set.size(), statSetParam, chl, otr, ots, sysRandomSeed());
					recver.sendInput(set, chl);
					writeOutput(outPath, ft, recver.mIntersection);
				}
#else 
				throw std::runtime_error("ENABLE_RR17_PSI not defined.");
#endif
			}
			else if (cmd.isSet("ecdh"))
			{
#ifdef ENABLE_ECDH_PSI
				padSmallSet(set, theirSize, cmd);

				if (r == Role::Sender)
				{
					EcdhPsiSender sender;
					sender.init(set.size(), statSetParam, sysRandomSeed());
					sender.sendInput(set, span<Channel>{&chl, 1});
				}
				else
				{
					EcdhPsiReceiver recver;
					recver.init(set.size(), statSetParam, sysRandomSeed());
					recver.sendInput(set, span<Channel>{&chl, 1});
					writeOutput(outPath, ft, recver.mIntersection);
				}
#else 
				throw std::runtime_error("ENABLE_ECDH_PSI not defined.");
#endif
			}
			else
			{
				throw std::runtime_error("Please add one of the protocol flags, -kkrt, -rr17a, -ecdh");
			}

		}
		catch (std::exception& e)
		{
			std::cout << Color::Red << "Exception: " << e.what() << std::endl << Color::Default;

			std::cout << "Try adding command line argument -debug" << std::endl;
		}
	}

}