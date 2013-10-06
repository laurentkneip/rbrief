    for (int i = 0; i < (int)keypoints.size(); ++i)
    {
        uchar* desc = descriptors.ptr(i);
        const KeyPoint& pt = keypoints[i];

        desc[0] =((smoothedSum(sum, pt, pattern[0].first.second, pattern[0].first.first) < smoothedSum(sum, pt, pattern[0].second.second, pattern[0].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[1].first.second, pattern[1].first.first) < smoothedSum(sum, pt, pattern[1].second.second, pattern[1].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[2].first.second, pattern[2].first.first) < smoothedSum(sum, pt, pattern[2].second.second, pattern[2].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[3].first.second, pattern[3].first.first) < smoothedSum(sum, pt, pattern[3].second.second, pattern[3].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[4].first.second, pattern[4].first.first) < smoothedSum(sum, pt, pattern[4].second.second, pattern[4].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[5].first.second, pattern[5].first.first) < smoothedSum(sum, pt, pattern[5].second.second, pattern[5].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[6].first.second, pattern[6].first.first) < smoothedSum(sum, pt, pattern[6].second.second, pattern[6].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[7].first.second, pattern[7].first.first) < smoothedSum(sum, pt, pattern[7].second.second, pattern[7].second.first)) << 0);
        desc[1] =((smoothedSum(sum, pt, pattern[8].first.second, pattern[8].first.first) < smoothedSum(sum, pt, pattern[8].second.second, pattern[8].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[9].first.second, pattern[9].first.first) < smoothedSum(sum, pt, pattern[9].second.second, pattern[9].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[10].first.second, pattern[10].first.first) < smoothedSum(sum, pt, pattern[10].second.second, pattern[10].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[11].first.second, pattern[11].first.first) < smoothedSum(sum, pt, pattern[11].second.second, pattern[11].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[12].first.second, pattern[12].first.first) < smoothedSum(sum, pt, pattern[12].second.second, pattern[12].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[13].first.second, pattern[13].first.first) < smoothedSum(sum, pt, pattern[13].second.second, pattern[13].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[14].first.second, pattern[14].first.first) < smoothedSum(sum, pt, pattern[14].second.second, pattern[14].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[15].first.second, pattern[15].first.first) < smoothedSum(sum, pt, pattern[15].second.second, pattern[15].second.first)) << 0);
        desc[2] =((smoothedSum(sum, pt, pattern[16].first.second, pattern[16].first.first) < smoothedSum(sum, pt, pattern[16].second.second, pattern[16].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[17].first.second, pattern[17].first.first) < smoothedSum(sum, pt, pattern[17].second.second, pattern[17].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[18].first.second, pattern[18].first.first) < smoothedSum(sum, pt, pattern[18].second.second, pattern[18].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[19].first.second, pattern[19].first.first) < smoothedSum(sum, pt, pattern[19].second.second, pattern[19].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[20].first.second, pattern[20].first.first) < smoothedSum(sum, pt, pattern[20].second.second, pattern[20].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[21].first.second, pattern[21].first.first) < smoothedSum(sum, pt, pattern[21].second.second, pattern[21].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[22].first.second, pattern[22].first.first) < smoothedSum(sum, pt, pattern[22].second.second, pattern[22].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[23].first.second, pattern[23].first.first) < smoothedSum(sum, pt, pattern[23].second.second, pattern[23].second.first)) << 0);
        desc[3] =((smoothedSum(sum, pt, pattern[24].first.second, pattern[24].first.first) < smoothedSum(sum, pt, pattern[24].second.second, pattern[24].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[25].first.second, pattern[25].first.first) < smoothedSum(sum, pt, pattern[25].second.second, pattern[25].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[26].first.second, pattern[26].first.first) < smoothedSum(sum, pt, pattern[26].second.second, pattern[26].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[27].first.second, pattern[27].first.first) < smoothedSum(sum, pt, pattern[27].second.second, pattern[27].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[28].first.second, pattern[28].first.first) < smoothedSum(sum, pt, pattern[28].second.second, pattern[28].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[29].first.second, pattern[29].first.first) < smoothedSum(sum, pt, pattern[29].second.second, pattern[29].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[30].first.second, pattern[30].first.first) < smoothedSum(sum, pt, pattern[30].second.second, pattern[30].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[31].first.second, pattern[31].first.first) < smoothedSum(sum, pt, pattern[31].second.second, pattern[31].second.first)) << 0);
        desc[4] =((smoothedSum(sum, pt, pattern[32].first.second, pattern[32].first.first) < smoothedSum(sum, pt, pattern[32].second.second, pattern[32].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[33].first.second, pattern[33].first.first) < smoothedSum(sum, pt, pattern[33].second.second, pattern[33].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[34].first.second, pattern[34].first.first) < smoothedSum(sum, pt, pattern[34].second.second, pattern[34].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[35].first.second, pattern[35].first.first) < smoothedSum(sum, pt, pattern[35].second.second, pattern[35].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[36].first.second, pattern[36].first.first) < smoothedSum(sum, pt, pattern[36].second.second, pattern[36].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[37].first.second, pattern[37].first.first) < smoothedSum(sum, pt, pattern[37].second.second, pattern[37].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[38].first.second, pattern[38].first.first) < smoothedSum(sum, pt, pattern[38].second.second, pattern[38].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[39].first.second, pattern[39].first.first) < smoothedSum(sum, pt, pattern[39].second.second, pattern[39].second.first)) << 0);
        desc[5] =((smoothedSum(sum, pt, pattern[40].first.second, pattern[40].first.first) < smoothedSum(sum, pt, pattern[40].second.second, pattern[40].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[41].first.second, pattern[41].first.first) < smoothedSum(sum, pt, pattern[41].second.second, pattern[41].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[42].first.second, pattern[42].first.first) < smoothedSum(sum, pt, pattern[42].second.second, pattern[42].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[43].first.second, pattern[43].first.first) < smoothedSum(sum, pt, pattern[43].second.second, pattern[43].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[44].first.second, pattern[44].first.first) < smoothedSum(sum, pt, pattern[44].second.second, pattern[44].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[45].first.second, pattern[45].first.first) < smoothedSum(sum, pt, pattern[45].second.second, pattern[45].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[46].first.second, pattern[46].first.first) < smoothedSum(sum, pt, pattern[46].second.second, pattern[46].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[47].first.second, pattern[47].first.first) < smoothedSum(sum, pt, pattern[47].second.second, pattern[47].second.first)) << 0);
        desc[6] =((smoothedSum(sum, pt, pattern[48].first.second, pattern[48].first.first) < smoothedSum(sum, pt, pattern[48].second.second, pattern[48].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[49].first.second, pattern[49].first.first) < smoothedSum(sum, pt, pattern[49].second.second, pattern[49].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[50].first.second, pattern[50].first.first) < smoothedSum(sum, pt, pattern[50].second.second, pattern[50].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[51].first.second, pattern[51].first.first) < smoothedSum(sum, pt, pattern[51].second.second, pattern[51].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[52].first.second, pattern[52].first.first) < smoothedSum(sum, pt, pattern[52].second.second, pattern[52].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[53].first.second, pattern[53].first.first) < smoothedSum(sum, pt, pattern[53].second.second, pattern[53].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[54].first.second, pattern[54].first.first) < smoothedSum(sum, pt, pattern[54].second.second, pattern[54].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[55].first.second, pattern[55].first.first) < smoothedSum(sum, pt, pattern[55].second.second, pattern[55].second.first)) << 0);
        desc[7] =((smoothedSum(sum, pt, pattern[56].first.second, pattern[56].first.first) < smoothedSum(sum, pt, pattern[56].second.second, pattern[56].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[57].first.second, pattern[57].first.first) < smoothedSum(sum, pt, pattern[57].second.second, pattern[57].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[58].first.second, pattern[58].first.first) < smoothedSum(sum, pt, pattern[58].second.second, pattern[58].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[59].first.second, pattern[59].first.first) < smoothedSum(sum, pt, pattern[59].second.second, pattern[59].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[60].first.second, pattern[60].first.first) < smoothedSum(sum, pt, pattern[60].second.second, pattern[60].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[61].first.second, pattern[61].first.first) < smoothedSum(sum, pt, pattern[61].second.second, pattern[61].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[62].first.second, pattern[62].first.first) < smoothedSum(sum, pt, pattern[62].second.second, pattern[62].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[63].first.second, pattern[63].first.first) < smoothedSum(sum, pt, pattern[63].second.second, pattern[63].second.first)) << 0);
        desc[8] =((smoothedSum(sum, pt, pattern[64].first.second, pattern[64].first.first) < smoothedSum(sum, pt, pattern[64].second.second, pattern[64].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[65].first.second, pattern[65].first.first) < smoothedSum(sum, pt, pattern[65].second.second, pattern[65].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[66].first.second, pattern[66].first.first) < smoothedSum(sum, pt, pattern[66].second.second, pattern[66].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[67].first.second, pattern[67].first.first) < smoothedSum(sum, pt, pattern[67].second.second, pattern[67].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[68].first.second, pattern[68].first.first) < smoothedSum(sum, pt, pattern[68].second.second, pattern[68].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[69].first.second, pattern[69].first.first) < smoothedSum(sum, pt, pattern[69].second.second, pattern[69].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[70].first.second, pattern[70].first.first) < smoothedSum(sum, pt, pattern[70].second.second, pattern[70].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[71].first.second, pattern[71].first.first) < smoothedSum(sum, pt, pattern[71].second.second, pattern[71].second.first)) << 0);
        desc[9] =((smoothedSum(sum, pt, pattern[72].first.second, pattern[72].first.first) < smoothedSum(sum, pt, pattern[72].second.second, pattern[72].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[73].first.second, pattern[73].first.first) < smoothedSum(sum, pt, pattern[73].second.second, pattern[73].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[74].first.second, pattern[74].first.first) < smoothedSum(sum, pt, pattern[74].second.second, pattern[74].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[75].first.second, pattern[75].first.first) < smoothedSum(sum, pt, pattern[75].second.second, pattern[75].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[76].first.second, pattern[76].first.first) < smoothedSum(sum, pt, pattern[76].second.second, pattern[76].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[77].first.second, pattern[77].first.first) < smoothedSum(sum, pt, pattern[77].second.second, pattern[77].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[78].first.second, pattern[78].first.first) < smoothedSum(sum, pt, pattern[78].second.second, pattern[78].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[79].first.second, pattern[79].first.first) < smoothedSum(sum, pt, pattern[79].second.second, pattern[79].second.first)) << 0);
        desc[10] =((smoothedSum(sum, pt, pattern[80].first.second, pattern[80].first.first) < smoothedSum(sum, pt, pattern[80].second.second, pattern[80].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[81].first.second, pattern[81].first.first) < smoothedSum(sum, pt, pattern[81].second.second, pattern[81].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[82].first.second, pattern[82].first.first) < smoothedSum(sum, pt, pattern[82].second.second, pattern[82].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[83].first.second, pattern[83].first.first) < smoothedSum(sum, pt, pattern[83].second.second, pattern[83].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[84].first.second, pattern[84].first.first) < smoothedSum(sum, pt, pattern[84].second.second, pattern[84].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[85].first.second, pattern[85].first.first) < smoothedSum(sum, pt, pattern[85].second.second, pattern[85].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[86].first.second, pattern[86].first.first) < smoothedSum(sum, pt, pattern[86].second.second, pattern[86].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[87].first.second, pattern[87].first.first) < smoothedSum(sum, pt, pattern[87].second.second, pattern[87].second.first)) << 0);
        desc[11] =((smoothedSum(sum, pt, pattern[88].first.second, pattern[88].first.first) < smoothedSum(sum, pt, pattern[88].second.second, pattern[88].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[89].first.second, pattern[89].first.first) < smoothedSum(sum, pt, pattern[89].second.second, pattern[89].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[90].first.second, pattern[90].first.first) < smoothedSum(sum, pt, pattern[90].second.second, pattern[90].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[91].first.second, pattern[91].first.first) < smoothedSum(sum, pt, pattern[91].second.second, pattern[91].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[92].first.second, pattern[92].first.first) < smoothedSum(sum, pt, pattern[92].second.second, pattern[92].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[93].first.second, pattern[93].first.first) < smoothedSum(sum, pt, pattern[93].second.second, pattern[93].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[94].first.second, pattern[94].first.first) < smoothedSum(sum, pt, pattern[94].second.second, pattern[94].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[95].first.second, pattern[95].first.first) < smoothedSum(sum, pt, pattern[95].second.second, pattern[95].second.first)) << 0);
        desc[12] =((smoothedSum(sum, pt, pattern[96].first.second, pattern[96].first.first) < smoothedSum(sum, pt, pattern[96].second.second, pattern[96].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[97].first.second, pattern[97].first.first) < smoothedSum(sum, pt, pattern[97].second.second, pattern[97].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[98].first.second, pattern[98].first.first) < smoothedSum(sum, pt, pattern[98].second.second, pattern[98].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[99].first.second, pattern[99].first.first) < smoothedSum(sum, pt, pattern[99].second.second, pattern[99].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[100].first.second, pattern[100].first.first) < smoothedSum(sum, pt, pattern[100].second.second, pattern[100].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[101].first.second, pattern[101].first.first) < smoothedSum(sum, pt, pattern[101].second.second, pattern[101].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[102].first.second, pattern[102].first.first) < smoothedSum(sum, pt, pattern[102].second.second, pattern[102].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[103].first.second, pattern[103].first.first) < smoothedSum(sum, pt, pattern[103].second.second, pattern[103].second.first)) << 0);
        desc[13] =((smoothedSum(sum, pt, pattern[104].first.second, pattern[104].first.first) < smoothedSum(sum, pt, pattern[104].second.second, pattern[104].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[105].first.second, pattern[105].first.first) < smoothedSum(sum, pt, pattern[105].second.second, pattern[105].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[106].first.second, pattern[106].first.first) < smoothedSum(sum, pt, pattern[106].second.second, pattern[106].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[107].first.second, pattern[107].first.first) < smoothedSum(sum, pt, pattern[107].second.second, pattern[107].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[108].first.second, pattern[108].first.first) < smoothedSum(sum, pt, pattern[108].second.second, pattern[108].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[109].first.second, pattern[109].first.first) < smoothedSum(sum, pt, pattern[109].second.second, pattern[109].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[110].first.second, pattern[110].first.first) < smoothedSum(sum, pt, pattern[110].second.second, pattern[110].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[111].first.second, pattern[111].first.first) < smoothedSum(sum, pt, pattern[111].second.second, pattern[111].second.first)) << 0);
        desc[14] =((smoothedSum(sum, pt, pattern[112].first.second, pattern[112].first.first) < smoothedSum(sum, pt, pattern[112].second.second, pattern[112].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[113].first.second, pattern[113].first.first) < smoothedSum(sum, pt, pattern[113].second.second, pattern[113].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[114].first.second, pattern[114].first.first) < smoothedSum(sum, pt, pattern[114].second.second, pattern[114].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[115].first.second, pattern[115].first.first) < smoothedSum(sum, pt, pattern[115].second.second, pattern[115].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[116].first.second, pattern[116].first.first) < smoothedSum(sum, pt, pattern[116].second.second, pattern[116].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[117].first.second, pattern[117].first.first) < smoothedSum(sum, pt, pattern[117].second.second, pattern[117].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[118].first.second, pattern[118].first.first) < smoothedSum(sum, pt, pattern[118].second.second, pattern[118].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[119].first.second, pattern[119].first.first) < smoothedSum(sum, pt, pattern[119].second.second, pattern[119].second.first)) << 0);
        desc[15] =((smoothedSum(sum, pt, pattern[120].first.second, pattern[120].first.first) < smoothedSum(sum, pt, pattern[120].second.second, pattern[120].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[121].first.second, pattern[121].first.first) < smoothedSum(sum, pt, pattern[121].second.second, pattern[121].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[122].first.second, pattern[122].first.first) < smoothedSum(sum, pt, pattern[122].second.second, pattern[122].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[123].first.second, pattern[123].first.first) < smoothedSum(sum, pt, pattern[123].second.second, pattern[123].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[124].first.second, pattern[124].first.first) < smoothedSum(sum, pt, pattern[124].second.second, pattern[124].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[125].first.second, pattern[125].first.first) < smoothedSum(sum, pt, pattern[125].second.second, pattern[125].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[126].first.second, pattern[126].first.first) < smoothedSum(sum, pt, pattern[126].second.second, pattern[126].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[127].first.second, pattern[127].first.first) < smoothedSum(sum, pt, pattern[127].second.second, pattern[127].second.first)) << 0);
        desc[16] =((smoothedSum(sum, pt, pattern[128].first.second, pattern[128].first.first) < smoothedSum(sum, pt, pattern[128].second.second, pattern[128].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[129].first.second, pattern[129].first.first) < smoothedSum(sum, pt, pattern[129].second.second, pattern[129].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[130].first.second, pattern[130].first.first) < smoothedSum(sum, pt, pattern[130].second.second, pattern[130].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[131].first.second, pattern[131].first.first) < smoothedSum(sum, pt, pattern[131].second.second, pattern[131].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[132].first.second, pattern[132].first.first) < smoothedSum(sum, pt, pattern[132].second.second, pattern[132].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[133].first.second, pattern[133].first.first) < smoothedSum(sum, pt, pattern[133].second.second, pattern[133].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[134].first.second, pattern[134].first.first) < smoothedSum(sum, pt, pattern[134].second.second, pattern[134].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[135].first.second, pattern[135].first.first) < smoothedSum(sum, pt, pattern[135].second.second, pattern[135].second.first)) << 0);
        desc[17] =((smoothedSum(sum, pt, pattern[136].first.second, pattern[136].first.first) < smoothedSum(sum, pt, pattern[136].second.second, pattern[136].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[137].first.second, pattern[137].first.first) < smoothedSum(sum, pt, pattern[137].second.second, pattern[137].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[138].first.second, pattern[138].first.first) < smoothedSum(sum, pt, pattern[138].second.second, pattern[138].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[139].first.second, pattern[139].first.first) < smoothedSum(sum, pt, pattern[139].second.second, pattern[139].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[140].first.second, pattern[140].first.first) < smoothedSum(sum, pt, pattern[140].second.second, pattern[140].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[141].first.second, pattern[141].first.first) < smoothedSum(sum, pt, pattern[141].second.second, pattern[141].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[142].first.second, pattern[142].first.first) < smoothedSum(sum, pt, pattern[142].second.second, pattern[142].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[143].first.second, pattern[143].first.first) < smoothedSum(sum, pt, pattern[143].second.second, pattern[143].second.first)) << 0);
        desc[18] =((smoothedSum(sum, pt, pattern[144].first.second, pattern[144].first.first) < smoothedSum(sum, pt, pattern[144].second.second, pattern[144].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[145].first.second, pattern[145].first.first) < smoothedSum(sum, pt, pattern[145].second.second, pattern[145].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[146].first.second, pattern[146].first.first) < smoothedSum(sum, pt, pattern[146].second.second, pattern[146].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[147].first.second, pattern[147].first.first) < smoothedSum(sum, pt, pattern[147].second.second, pattern[147].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[148].first.second, pattern[148].first.first) < smoothedSum(sum, pt, pattern[148].second.second, pattern[148].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[149].first.second, pattern[149].first.first) < smoothedSum(sum, pt, pattern[149].second.second, pattern[149].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[150].first.second, pattern[150].first.first) < smoothedSum(sum, pt, pattern[150].second.second, pattern[150].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[151].first.second, pattern[151].first.first) < smoothedSum(sum, pt, pattern[151].second.second, pattern[151].second.first)) << 0);
        desc[19] =((smoothedSum(sum, pt, pattern[152].first.second, pattern[152].first.first) < smoothedSum(sum, pt, pattern[152].second.second, pattern[152].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[153].first.second, pattern[153].first.first) < smoothedSum(sum, pt, pattern[153].second.second, pattern[153].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[154].first.second, pattern[154].first.first) < smoothedSum(sum, pt, pattern[154].second.second, pattern[154].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[155].first.second, pattern[155].first.first) < smoothedSum(sum, pt, pattern[155].second.second, pattern[155].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[156].first.second, pattern[156].first.first) < smoothedSum(sum, pt, pattern[156].second.second, pattern[156].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[157].first.second, pattern[157].first.first) < smoothedSum(sum, pt, pattern[157].second.second, pattern[157].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[158].first.second, pattern[158].first.first) < smoothedSum(sum, pt, pattern[158].second.second, pattern[158].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[159].first.second, pattern[159].first.first) < smoothedSum(sum, pt, pattern[159].second.second, pattern[159].second.first)) << 0);
        desc[20] =((smoothedSum(sum, pt, pattern[160].first.second, pattern[160].first.first) < smoothedSum(sum, pt, pattern[160].second.second, pattern[160].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[161].first.second, pattern[161].first.first) < smoothedSum(sum, pt, pattern[161].second.second, pattern[161].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[162].first.second, pattern[162].first.first) < smoothedSum(sum, pt, pattern[162].second.second, pattern[162].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[163].first.second, pattern[163].first.first) < smoothedSum(sum, pt, pattern[163].second.second, pattern[163].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[164].first.second, pattern[164].first.first) < smoothedSum(sum, pt, pattern[164].second.second, pattern[164].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[165].first.second, pattern[165].first.first) < smoothedSum(sum, pt, pattern[165].second.second, pattern[165].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[166].first.second, pattern[166].first.first) < smoothedSum(sum, pt, pattern[166].second.second, pattern[166].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[167].first.second, pattern[167].first.first) < smoothedSum(sum, pt, pattern[167].second.second, pattern[167].second.first)) << 0);
        desc[21] =((smoothedSum(sum, pt, pattern[168].first.second, pattern[168].first.first) < smoothedSum(sum, pt, pattern[168].second.second, pattern[168].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[169].first.second, pattern[169].first.first) < smoothedSum(sum, pt, pattern[169].second.second, pattern[169].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[170].first.second, pattern[170].first.first) < smoothedSum(sum, pt, pattern[170].second.second, pattern[170].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[171].first.second, pattern[171].first.first) < smoothedSum(sum, pt, pattern[171].second.second, pattern[171].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[172].first.second, pattern[172].first.first) < smoothedSum(sum, pt, pattern[172].second.second, pattern[172].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[173].first.second, pattern[173].first.first) < smoothedSum(sum, pt, pattern[173].second.second, pattern[173].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[174].first.second, pattern[174].first.first) < smoothedSum(sum, pt, pattern[174].second.second, pattern[174].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[175].first.second, pattern[175].first.first) < smoothedSum(sum, pt, pattern[175].second.second, pattern[175].second.first)) << 0);
        desc[22] =((smoothedSum(sum, pt, pattern[176].first.second, pattern[176].first.first) < smoothedSum(sum, pt, pattern[176].second.second, pattern[176].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[177].first.second, pattern[177].first.first) < smoothedSum(sum, pt, pattern[177].second.second, pattern[177].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[178].first.second, pattern[178].first.first) < smoothedSum(sum, pt, pattern[178].second.second, pattern[178].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[179].first.second, pattern[179].first.first) < smoothedSum(sum, pt, pattern[179].second.second, pattern[179].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[180].first.second, pattern[180].first.first) < smoothedSum(sum, pt, pattern[180].second.second, pattern[180].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[181].first.second, pattern[181].first.first) < smoothedSum(sum, pt, pattern[181].second.second, pattern[181].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[182].first.second, pattern[182].first.first) < smoothedSum(sum, pt, pattern[182].second.second, pattern[182].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[183].first.second, pattern[183].first.first) < smoothedSum(sum, pt, pattern[183].second.second, pattern[183].second.first)) << 0);
        desc[23] =((smoothedSum(sum, pt, pattern[184].first.second, pattern[184].first.first) < smoothedSum(sum, pt, pattern[184].second.second, pattern[184].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[185].first.second, pattern[185].first.first) < smoothedSum(sum, pt, pattern[185].second.second, pattern[185].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[186].first.second, pattern[186].first.first) < smoothedSum(sum, pt, pattern[186].second.second, pattern[186].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[187].first.second, pattern[187].first.first) < smoothedSum(sum, pt, pattern[187].second.second, pattern[187].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[188].first.second, pattern[188].first.first) < smoothedSum(sum, pt, pattern[188].second.second, pattern[188].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[189].first.second, pattern[189].first.first) < smoothedSum(sum, pt, pattern[189].second.second, pattern[189].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[190].first.second, pattern[190].first.first) < smoothedSum(sum, pt, pattern[190].second.second, pattern[190].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[191].first.second, pattern[191].first.first) < smoothedSum(sum, pt, pattern[191].second.second, pattern[191].second.first)) << 0);
        desc[24] =((smoothedSum(sum, pt, pattern[192].first.second, pattern[192].first.first) < smoothedSum(sum, pt, pattern[192].second.second, pattern[192].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[193].first.second, pattern[193].first.first) < smoothedSum(sum, pt, pattern[193].second.second, pattern[193].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[194].first.second, pattern[194].first.first) < smoothedSum(sum, pt, pattern[194].second.second, pattern[194].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[195].first.second, pattern[195].first.first) < smoothedSum(sum, pt, pattern[195].second.second, pattern[195].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[196].first.second, pattern[196].first.first) < smoothedSum(sum, pt, pattern[196].second.second, pattern[196].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[197].first.second, pattern[197].first.first) < smoothedSum(sum, pt, pattern[197].second.second, pattern[197].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[198].first.second, pattern[198].first.first) < smoothedSum(sum, pt, pattern[198].second.second, pattern[198].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[199].first.second, pattern[199].first.first) < smoothedSum(sum, pt, pattern[199].second.second, pattern[199].second.first)) << 0);
        desc[25] =((smoothedSum(sum, pt, pattern[200].first.second, pattern[200].first.first) < smoothedSum(sum, pt, pattern[200].second.second, pattern[200].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[201].first.second, pattern[201].first.first) < smoothedSum(sum, pt, pattern[201].second.second, pattern[201].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[202].first.second, pattern[202].first.first) < smoothedSum(sum, pt, pattern[202].second.second, pattern[202].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[203].first.second, pattern[203].first.first) < smoothedSum(sum, pt, pattern[203].second.second, pattern[203].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[204].first.second, pattern[204].first.first) < smoothedSum(sum, pt, pattern[204].second.second, pattern[204].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[205].first.second, pattern[205].first.first) < smoothedSum(sum, pt, pattern[205].second.second, pattern[205].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[206].first.second, pattern[206].first.first) < smoothedSum(sum, pt, pattern[206].second.second, pattern[206].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[207].first.second, pattern[207].first.first) < smoothedSum(sum, pt, pattern[207].second.second, pattern[207].second.first)) << 0);
        desc[26] =((smoothedSum(sum, pt, pattern[208].first.second, pattern[208].first.first) < smoothedSum(sum, pt, pattern[208].second.second, pattern[208].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[209].first.second, pattern[209].first.first) < smoothedSum(sum, pt, pattern[209].second.second, pattern[209].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[210].first.second, pattern[210].first.first) < smoothedSum(sum, pt, pattern[210].second.second, pattern[210].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[211].first.second, pattern[211].first.first) < smoothedSum(sum, pt, pattern[211].second.second, pattern[211].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[212].first.second, pattern[212].first.first) < smoothedSum(sum, pt, pattern[212].second.second, pattern[212].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[213].first.second, pattern[213].first.first) < smoothedSum(sum, pt, pattern[213].second.second, pattern[213].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[214].first.second, pattern[214].first.first) < smoothedSum(sum, pt, pattern[214].second.second, pattern[214].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[215].first.second, pattern[215].first.first) < smoothedSum(sum, pt, pattern[215].second.second, pattern[215].second.first)) << 0);
        desc[27] =((smoothedSum(sum, pt, pattern[216].first.second, pattern[216].first.first) < smoothedSum(sum, pt, pattern[216].second.second, pattern[216].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[217].first.second, pattern[217].first.first) < smoothedSum(sum, pt, pattern[217].second.second, pattern[217].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[218].first.second, pattern[218].first.first) < smoothedSum(sum, pt, pattern[218].second.second, pattern[218].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[219].first.second, pattern[219].first.first) < smoothedSum(sum, pt, pattern[219].second.second, pattern[219].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[220].first.second, pattern[220].first.first) < smoothedSum(sum, pt, pattern[220].second.second, pattern[220].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[221].first.second, pattern[221].first.first) < smoothedSum(sum, pt, pattern[221].second.second, pattern[221].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[222].first.second, pattern[222].first.first) < smoothedSum(sum, pt, pattern[222].second.second, pattern[222].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[223].first.second, pattern[223].first.first) < smoothedSum(sum, pt, pattern[223].second.second, pattern[223].second.first)) << 0);
        desc[28] =((smoothedSum(sum, pt, pattern[224].first.second, pattern[224].first.first) < smoothedSum(sum, pt, pattern[224].second.second, pattern[224].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[225].first.second, pattern[225].first.first) < smoothedSum(sum, pt, pattern[225].second.second, pattern[225].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[226].first.second, pattern[226].first.first) < smoothedSum(sum, pt, pattern[226].second.second, pattern[226].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[227].first.second, pattern[227].first.first) < smoothedSum(sum, pt, pattern[227].second.second, pattern[227].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[228].first.second, pattern[228].first.first) < smoothedSum(sum, pt, pattern[228].second.second, pattern[228].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[229].first.second, pattern[229].first.first) < smoothedSum(sum, pt, pattern[229].second.second, pattern[229].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[230].first.second, pattern[230].first.first) < smoothedSum(sum, pt, pattern[230].second.second, pattern[230].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[231].first.second, pattern[231].first.first) < smoothedSum(sum, pt, pattern[231].second.second, pattern[231].second.first)) << 0);
        desc[29] =((smoothedSum(sum, pt, pattern[232].first.second, pattern[232].first.first) < smoothedSum(sum, pt, pattern[232].second.second, pattern[232].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[233].first.second, pattern[233].first.first) < smoothedSum(sum, pt, pattern[233].second.second, pattern[233].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[234].first.second, pattern[234].first.first) < smoothedSum(sum, pt, pattern[234].second.second, pattern[234].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[235].first.second, pattern[235].first.first) < smoothedSum(sum, pt, pattern[235].second.second, pattern[235].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[236].first.second, pattern[236].first.first) < smoothedSum(sum, pt, pattern[236].second.second, pattern[236].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[237].first.second, pattern[237].first.first) < smoothedSum(sum, pt, pattern[237].second.second, pattern[237].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[238].first.second, pattern[238].first.first) < smoothedSum(sum, pt, pattern[238].second.second, pattern[238].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[239].first.second, pattern[239].first.first) < smoothedSum(sum, pt, pattern[239].second.second, pattern[239].second.first)) << 0);
        desc[30] =((smoothedSum(sum, pt, pattern[240].first.second, pattern[240].first.first) < smoothedSum(sum, pt, pattern[240].second.second, pattern[240].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[241].first.second, pattern[241].first.first) < smoothedSum(sum, pt, pattern[241].second.second, pattern[241].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[242].first.second, pattern[242].first.first) < smoothedSum(sum, pt, pattern[242].second.second, pattern[242].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[243].first.second, pattern[243].first.first) < smoothedSum(sum, pt, pattern[243].second.second, pattern[243].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[244].first.second, pattern[244].first.first) < smoothedSum(sum, pt, pattern[244].second.second, pattern[244].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[245].first.second, pattern[245].first.first) < smoothedSum(sum, pt, pattern[245].second.second, pattern[245].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[246].first.second, pattern[246].first.first) < smoothedSum(sum, pt, pattern[246].second.second, pattern[246].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[247].first.second, pattern[247].first.first) < smoothedSum(sum, pt, pattern[247].second.second, pattern[247].second.first)) << 0);
        desc[31] =((smoothedSum(sum, pt, pattern[248].first.second, pattern[248].first.first) < smoothedSum(sum, pt, pattern[248].second.second, pattern[248].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[249].first.second, pattern[249].first.first) < smoothedSum(sum, pt, pattern[249].second.second, pattern[249].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[250].first.second, pattern[250].first.first) < smoothedSum(sum, pt, pattern[250].second.second, pattern[250].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[251].first.second, pattern[251].first.first) < smoothedSum(sum, pt, pattern[251].second.second, pattern[251].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[252].first.second, pattern[252].first.first) < smoothedSum(sum, pt, pattern[252].second.second, pattern[252].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[253].first.second, pattern[253].first.first) < smoothedSum(sum, pt, pattern[253].second.second, pattern[253].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[254].first.second, pattern[254].first.first) < smoothedSum(sum, pt, pattern[254].second.second, pattern[254].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[255].first.second, pattern[255].first.first) < smoothedSum(sum, pt, pattern[255].second.second, pattern[255].second.first)) << 0);
    }