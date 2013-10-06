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
        desc[32] =((smoothedSum(sum, pt, pattern[256].first.second, pattern[256].first.first) < smoothedSum(sum, pt, pattern[256].second.second, pattern[256].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[257].first.second, pattern[257].first.first) < smoothedSum(sum, pt, pattern[257].second.second, pattern[257].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[258].first.second, pattern[258].first.first) < smoothedSum(sum, pt, pattern[258].second.second, pattern[258].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[259].first.second, pattern[259].first.first) < smoothedSum(sum, pt, pattern[259].second.second, pattern[259].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[260].first.second, pattern[260].first.first) < smoothedSum(sum, pt, pattern[260].second.second, pattern[260].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[261].first.second, pattern[261].first.first) < smoothedSum(sum, pt, pattern[261].second.second, pattern[261].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[262].first.second, pattern[262].first.first) < smoothedSum(sum, pt, pattern[262].second.second, pattern[262].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[263].first.second, pattern[263].first.first) < smoothedSum(sum, pt, pattern[263].second.second, pattern[263].second.first)) << 0);
        desc[33] =((smoothedSum(sum, pt, pattern[264].first.second, pattern[264].first.first) < smoothedSum(sum, pt, pattern[264].second.second, pattern[264].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[265].first.second, pattern[265].first.first) < smoothedSum(sum, pt, pattern[265].second.second, pattern[265].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[266].first.second, pattern[266].first.first) < smoothedSum(sum, pt, pattern[266].second.second, pattern[266].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[267].first.second, pattern[267].first.first) < smoothedSum(sum, pt, pattern[267].second.second, pattern[267].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[268].first.second, pattern[268].first.first) < smoothedSum(sum, pt, pattern[268].second.second, pattern[268].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[269].first.second, pattern[269].first.first) < smoothedSum(sum, pt, pattern[269].second.second, pattern[269].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[270].first.second, pattern[270].first.first) < smoothedSum(sum, pt, pattern[270].second.second, pattern[270].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[271].first.second, pattern[271].first.first) < smoothedSum(sum, pt, pattern[271].second.second, pattern[271].second.first)) << 0);
        desc[34] =((smoothedSum(sum, pt, pattern[272].first.second, pattern[272].first.first) < smoothedSum(sum, pt, pattern[272].second.second, pattern[272].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[273].first.second, pattern[273].first.first) < smoothedSum(sum, pt, pattern[273].second.second, pattern[273].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[274].first.second, pattern[274].first.first) < smoothedSum(sum, pt, pattern[274].second.second, pattern[274].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[275].first.second, pattern[275].first.first) < smoothedSum(sum, pt, pattern[275].second.second, pattern[275].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[276].first.second, pattern[276].first.first) < smoothedSum(sum, pt, pattern[276].second.second, pattern[276].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[277].first.second, pattern[277].first.first) < smoothedSum(sum, pt, pattern[277].second.second, pattern[277].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[278].first.second, pattern[278].first.first) < smoothedSum(sum, pt, pattern[278].second.second, pattern[278].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[279].first.second, pattern[279].first.first) < smoothedSum(sum, pt, pattern[279].second.second, pattern[279].second.first)) << 0);
        desc[35] =((smoothedSum(sum, pt, pattern[280].first.second, pattern[280].first.first) < smoothedSum(sum, pt, pattern[280].second.second, pattern[280].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[281].first.second, pattern[281].first.first) < smoothedSum(sum, pt, pattern[281].second.second, pattern[281].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[282].first.second, pattern[282].first.first) < smoothedSum(sum, pt, pattern[282].second.second, pattern[282].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[283].first.second, pattern[283].first.first) < smoothedSum(sum, pt, pattern[283].second.second, pattern[283].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[284].first.second, pattern[284].first.first) < smoothedSum(sum, pt, pattern[284].second.second, pattern[284].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[285].first.second, pattern[285].first.first) < smoothedSum(sum, pt, pattern[285].second.second, pattern[285].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[286].first.second, pattern[286].first.first) < smoothedSum(sum, pt, pattern[286].second.second, pattern[286].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[287].first.second, pattern[287].first.first) < smoothedSum(sum, pt, pattern[287].second.second, pattern[287].second.first)) << 0);
        desc[36] =((smoothedSum(sum, pt, pattern[288].first.second, pattern[288].first.first) < smoothedSum(sum, pt, pattern[288].second.second, pattern[288].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[289].first.second, pattern[289].first.first) < smoothedSum(sum, pt, pattern[289].second.second, pattern[289].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[290].first.second, pattern[290].first.first) < smoothedSum(sum, pt, pattern[290].second.second, pattern[290].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[291].first.second, pattern[291].first.first) < smoothedSum(sum, pt, pattern[291].second.second, pattern[291].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[292].first.second, pattern[292].first.first) < smoothedSum(sum, pt, pattern[292].second.second, pattern[292].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[293].first.second, pattern[293].first.first) < smoothedSum(sum, pt, pattern[293].second.second, pattern[293].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[294].first.second, pattern[294].first.first) < smoothedSum(sum, pt, pattern[294].second.second, pattern[294].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[295].first.second, pattern[295].first.first) < smoothedSum(sum, pt, pattern[295].second.second, pattern[295].second.first)) << 0);
        desc[37] =((smoothedSum(sum, pt, pattern[296].first.second, pattern[296].first.first) < smoothedSum(sum, pt, pattern[296].second.second, pattern[296].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[297].first.second, pattern[297].first.first) < smoothedSum(sum, pt, pattern[297].second.second, pattern[297].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[298].first.second, pattern[298].first.first) < smoothedSum(sum, pt, pattern[298].second.second, pattern[298].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[299].first.second, pattern[299].first.first) < smoothedSum(sum, pt, pattern[299].second.second, pattern[299].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[300].first.second, pattern[300].first.first) < smoothedSum(sum, pt, pattern[300].second.second, pattern[300].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[301].first.second, pattern[301].first.first) < smoothedSum(sum, pt, pattern[301].second.second, pattern[301].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[302].first.second, pattern[302].first.first) < smoothedSum(sum, pt, pattern[302].second.second, pattern[302].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[303].first.second, pattern[303].first.first) < smoothedSum(sum, pt, pattern[303].second.second, pattern[303].second.first)) << 0);
        desc[38] =((smoothedSum(sum, pt, pattern[304].first.second, pattern[304].first.first) < smoothedSum(sum, pt, pattern[304].second.second, pattern[304].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[305].first.second, pattern[305].first.first) < smoothedSum(sum, pt, pattern[305].second.second, pattern[305].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[306].first.second, pattern[306].first.first) < smoothedSum(sum, pt, pattern[306].second.second, pattern[306].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[307].first.second, pattern[307].first.first) < smoothedSum(sum, pt, pattern[307].second.second, pattern[307].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[308].first.second, pattern[308].first.first) < smoothedSum(sum, pt, pattern[308].second.second, pattern[308].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[309].first.second, pattern[309].first.first) < smoothedSum(sum, pt, pattern[309].second.second, pattern[309].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[310].first.second, pattern[310].first.first) < smoothedSum(sum, pt, pattern[310].second.second, pattern[310].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[311].first.second, pattern[311].first.first) < smoothedSum(sum, pt, pattern[311].second.second, pattern[311].second.first)) << 0);
        desc[39] =((smoothedSum(sum, pt, pattern[312].first.second, pattern[312].first.first) < smoothedSum(sum, pt, pattern[312].second.second, pattern[312].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[313].first.second, pattern[313].first.first) < smoothedSum(sum, pt, pattern[313].second.second, pattern[313].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[314].first.second, pattern[314].first.first) < smoothedSum(sum, pt, pattern[314].second.second, pattern[314].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[315].first.second, pattern[315].first.first) < smoothedSum(sum, pt, pattern[315].second.second, pattern[315].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[316].first.second, pattern[316].first.first) < smoothedSum(sum, pt, pattern[316].second.second, pattern[316].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[317].first.second, pattern[317].first.first) < smoothedSum(sum, pt, pattern[317].second.second, pattern[317].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[318].first.second, pattern[318].first.first) < smoothedSum(sum, pt, pattern[318].second.second, pattern[318].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[319].first.second, pattern[319].first.first) < smoothedSum(sum, pt, pattern[319].second.second, pattern[319].second.first)) << 0);
        desc[40] =((smoothedSum(sum, pt, pattern[320].first.second, pattern[320].first.first) < smoothedSum(sum, pt, pattern[320].second.second, pattern[320].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[321].first.second, pattern[321].first.first) < smoothedSum(sum, pt, pattern[321].second.second, pattern[321].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[322].first.second, pattern[322].first.first) < smoothedSum(sum, pt, pattern[322].second.second, pattern[322].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[323].first.second, pattern[323].first.first) < smoothedSum(sum, pt, pattern[323].second.second, pattern[323].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[324].first.second, pattern[324].first.first) < smoothedSum(sum, pt, pattern[324].second.second, pattern[324].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[325].first.second, pattern[325].first.first) < smoothedSum(sum, pt, pattern[325].second.second, pattern[325].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[326].first.second, pattern[326].first.first) < smoothedSum(sum, pt, pattern[326].second.second, pattern[326].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[327].first.second, pattern[327].first.first) < smoothedSum(sum, pt, pattern[327].second.second, pattern[327].second.first)) << 0);
        desc[41] =((smoothedSum(sum, pt, pattern[328].first.second, pattern[328].first.first) < smoothedSum(sum, pt, pattern[328].second.second, pattern[328].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[329].first.second, pattern[329].first.first) < smoothedSum(sum, pt, pattern[329].second.second, pattern[329].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[330].first.second, pattern[330].first.first) < smoothedSum(sum, pt, pattern[330].second.second, pattern[330].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[331].first.second, pattern[331].first.first) < smoothedSum(sum, pt, pattern[331].second.second, pattern[331].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[332].first.second, pattern[332].first.first) < smoothedSum(sum, pt, pattern[332].second.second, pattern[332].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[333].first.second, pattern[333].first.first) < smoothedSum(sum, pt, pattern[333].second.second, pattern[333].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[334].first.second, pattern[334].first.first) < smoothedSum(sum, pt, pattern[334].second.second, pattern[334].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[335].first.second, pattern[335].first.first) < smoothedSum(sum, pt, pattern[335].second.second, pattern[335].second.first)) << 0);
        desc[42] =((smoothedSum(sum, pt, pattern[336].first.second, pattern[336].first.first) < smoothedSum(sum, pt, pattern[336].second.second, pattern[336].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[337].first.second, pattern[337].first.first) < smoothedSum(sum, pt, pattern[337].second.second, pattern[337].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[338].first.second, pattern[338].first.first) < smoothedSum(sum, pt, pattern[338].second.second, pattern[338].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[339].first.second, pattern[339].first.first) < smoothedSum(sum, pt, pattern[339].second.second, pattern[339].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[340].first.second, pattern[340].first.first) < smoothedSum(sum, pt, pattern[340].second.second, pattern[340].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[341].first.second, pattern[341].first.first) < smoothedSum(sum, pt, pattern[341].second.second, pattern[341].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[342].first.second, pattern[342].first.first) < smoothedSum(sum, pt, pattern[342].second.second, pattern[342].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[343].first.second, pattern[343].first.first) < smoothedSum(sum, pt, pattern[343].second.second, pattern[343].second.first)) << 0);
        desc[43] =((smoothedSum(sum, pt, pattern[344].first.second, pattern[344].first.first) < smoothedSum(sum, pt, pattern[344].second.second, pattern[344].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[345].first.second, pattern[345].first.first) < smoothedSum(sum, pt, pattern[345].second.second, pattern[345].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[346].first.second, pattern[346].first.first) < smoothedSum(sum, pt, pattern[346].second.second, pattern[346].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[347].first.second, pattern[347].first.first) < smoothedSum(sum, pt, pattern[347].second.second, pattern[347].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[348].first.second, pattern[348].first.first) < smoothedSum(sum, pt, pattern[348].second.second, pattern[348].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[349].first.second, pattern[349].first.first) < smoothedSum(sum, pt, pattern[349].second.second, pattern[349].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[350].first.second, pattern[350].first.first) < smoothedSum(sum, pt, pattern[350].second.second, pattern[350].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[351].first.second, pattern[351].first.first) < smoothedSum(sum, pt, pattern[351].second.second, pattern[351].second.first)) << 0);
        desc[44] =((smoothedSum(sum, pt, pattern[352].first.second, pattern[352].first.first) < smoothedSum(sum, pt, pattern[352].second.second, pattern[352].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[353].first.second, pattern[353].first.first) < smoothedSum(sum, pt, pattern[353].second.second, pattern[353].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[354].first.second, pattern[354].first.first) < smoothedSum(sum, pt, pattern[354].second.second, pattern[354].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[355].first.second, pattern[355].first.first) < smoothedSum(sum, pt, pattern[355].second.second, pattern[355].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[356].first.second, pattern[356].first.first) < smoothedSum(sum, pt, pattern[356].second.second, pattern[356].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[357].first.second, pattern[357].first.first) < smoothedSum(sum, pt, pattern[357].second.second, pattern[357].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[358].first.second, pattern[358].first.first) < smoothedSum(sum, pt, pattern[358].second.second, pattern[358].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[359].first.second, pattern[359].first.first) < smoothedSum(sum, pt, pattern[359].second.second, pattern[359].second.first)) << 0);
        desc[45] =((smoothedSum(sum, pt, pattern[360].first.second, pattern[360].first.first) < smoothedSum(sum, pt, pattern[360].second.second, pattern[360].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[361].first.second, pattern[361].first.first) < smoothedSum(sum, pt, pattern[361].second.second, pattern[361].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[362].first.second, pattern[362].first.first) < smoothedSum(sum, pt, pattern[362].second.second, pattern[362].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[363].first.second, pattern[363].first.first) < smoothedSum(sum, pt, pattern[363].second.second, pattern[363].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[364].first.second, pattern[364].first.first) < smoothedSum(sum, pt, pattern[364].second.second, pattern[364].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[365].first.second, pattern[365].first.first) < smoothedSum(sum, pt, pattern[365].second.second, pattern[365].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[366].first.second, pattern[366].first.first) < smoothedSum(sum, pt, pattern[366].second.second, pattern[366].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[367].first.second, pattern[367].first.first) < smoothedSum(sum, pt, pattern[367].second.second, pattern[367].second.first)) << 0);
        desc[46] =((smoothedSum(sum, pt, pattern[368].first.second, pattern[368].first.first) < smoothedSum(sum, pt, pattern[368].second.second, pattern[368].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[369].first.second, pattern[369].first.first) < smoothedSum(sum, pt, pattern[369].second.second, pattern[369].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[370].first.second, pattern[370].first.first) < smoothedSum(sum, pt, pattern[370].second.second, pattern[370].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[371].first.second, pattern[371].first.first) < smoothedSum(sum, pt, pattern[371].second.second, pattern[371].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[372].first.second, pattern[372].first.first) < smoothedSum(sum, pt, pattern[372].second.second, pattern[372].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[373].first.second, pattern[373].first.first) < smoothedSum(sum, pt, pattern[373].second.second, pattern[373].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[374].first.second, pattern[374].first.first) < smoothedSum(sum, pt, pattern[374].second.second, pattern[374].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[375].first.second, pattern[375].first.first) < smoothedSum(sum, pt, pattern[375].second.second, pattern[375].second.first)) << 0);
        desc[47] =((smoothedSum(sum, pt, pattern[376].first.second, pattern[376].first.first) < smoothedSum(sum, pt, pattern[376].second.second, pattern[376].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[377].first.second, pattern[377].first.first) < smoothedSum(sum, pt, pattern[377].second.second, pattern[377].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[378].first.second, pattern[378].first.first) < smoothedSum(sum, pt, pattern[378].second.second, pattern[378].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[379].first.second, pattern[379].first.first) < smoothedSum(sum, pt, pattern[379].second.second, pattern[379].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[380].first.second, pattern[380].first.first) < smoothedSum(sum, pt, pattern[380].second.second, pattern[380].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[381].first.second, pattern[381].first.first) < smoothedSum(sum, pt, pattern[381].second.second, pattern[381].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[382].first.second, pattern[382].first.first) < smoothedSum(sum, pt, pattern[382].second.second, pattern[382].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[383].first.second, pattern[383].first.first) < smoothedSum(sum, pt, pattern[383].second.second, pattern[383].second.first)) << 0);
        desc[48] =((smoothedSum(sum, pt, pattern[384].first.second, pattern[384].first.first) < smoothedSum(sum, pt, pattern[384].second.second, pattern[384].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[385].first.second, pattern[385].first.first) < smoothedSum(sum, pt, pattern[385].second.second, pattern[385].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[386].first.second, pattern[386].first.first) < smoothedSum(sum, pt, pattern[386].second.second, pattern[386].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[387].first.second, pattern[387].first.first) < smoothedSum(sum, pt, pattern[387].second.second, pattern[387].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[388].first.second, pattern[388].first.first) < smoothedSum(sum, pt, pattern[388].second.second, pattern[388].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[389].first.second, pattern[389].first.first) < smoothedSum(sum, pt, pattern[389].second.second, pattern[389].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[390].first.second, pattern[390].first.first) < smoothedSum(sum, pt, pattern[390].second.second, pattern[390].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[391].first.second, pattern[391].first.first) < smoothedSum(sum, pt, pattern[391].second.second, pattern[391].second.first)) << 0);
        desc[49] =((smoothedSum(sum, pt, pattern[392].first.second, pattern[392].first.first) < smoothedSum(sum, pt, pattern[392].second.second, pattern[392].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[393].first.second, pattern[393].first.first) < smoothedSum(sum, pt, pattern[393].second.second, pattern[393].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[394].first.second, pattern[394].first.first) < smoothedSum(sum, pt, pattern[394].second.second, pattern[394].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[395].first.second, pattern[395].first.first) < smoothedSum(sum, pt, pattern[395].second.second, pattern[395].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[396].first.second, pattern[396].first.first) < smoothedSum(sum, pt, pattern[396].second.second, pattern[396].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[397].first.second, pattern[397].first.first) < smoothedSum(sum, pt, pattern[397].second.second, pattern[397].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[398].first.second, pattern[398].first.first) < smoothedSum(sum, pt, pattern[398].second.second, pattern[398].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[399].first.second, pattern[399].first.first) < smoothedSum(sum, pt, pattern[399].second.second, pattern[399].second.first)) << 0);
        desc[50] =((smoothedSum(sum, pt, pattern[400].first.second, pattern[400].first.first) < smoothedSum(sum, pt, pattern[400].second.second, pattern[400].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[401].first.second, pattern[401].first.first) < smoothedSum(sum, pt, pattern[401].second.second, pattern[401].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[402].first.second, pattern[402].first.first) < smoothedSum(sum, pt, pattern[402].second.second, pattern[402].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[403].first.second, pattern[403].first.first) < smoothedSum(sum, pt, pattern[403].second.second, pattern[403].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[404].first.second, pattern[404].first.first) < smoothedSum(sum, pt, pattern[404].second.second, pattern[404].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[405].first.second, pattern[405].first.first) < smoothedSum(sum, pt, pattern[405].second.second, pattern[405].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[406].first.second, pattern[406].first.first) < smoothedSum(sum, pt, pattern[406].second.second, pattern[406].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[407].first.second, pattern[407].first.first) < smoothedSum(sum, pt, pattern[407].second.second, pattern[407].second.first)) << 0);
        desc[51] =((smoothedSum(sum, pt, pattern[408].first.second, pattern[408].first.first) < smoothedSum(sum, pt, pattern[408].second.second, pattern[408].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[409].first.second, pattern[409].first.first) < smoothedSum(sum, pt, pattern[409].second.second, pattern[409].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[410].first.second, pattern[410].first.first) < smoothedSum(sum, pt, pattern[410].second.second, pattern[410].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[411].first.second, pattern[411].first.first) < smoothedSum(sum, pt, pattern[411].second.second, pattern[411].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[412].first.second, pattern[412].first.first) < smoothedSum(sum, pt, pattern[412].second.second, pattern[412].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[413].first.second, pattern[413].first.first) < smoothedSum(sum, pt, pattern[413].second.second, pattern[413].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[414].first.second, pattern[414].first.first) < smoothedSum(sum, pt, pattern[414].second.second, pattern[414].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[415].first.second, pattern[415].first.first) < smoothedSum(sum, pt, pattern[415].second.second, pattern[415].second.first)) << 0);
        desc[52] =((smoothedSum(sum, pt, pattern[416].first.second, pattern[416].first.first) < smoothedSum(sum, pt, pattern[416].second.second, pattern[416].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[417].first.second, pattern[417].first.first) < smoothedSum(sum, pt, pattern[417].second.second, pattern[417].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[418].first.second, pattern[418].first.first) < smoothedSum(sum, pt, pattern[418].second.second, pattern[418].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[419].first.second, pattern[419].first.first) < smoothedSum(sum, pt, pattern[419].second.second, pattern[419].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[420].first.second, pattern[420].first.first) < smoothedSum(sum, pt, pattern[420].second.second, pattern[420].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[421].first.second, pattern[421].first.first) < smoothedSum(sum, pt, pattern[421].second.second, pattern[421].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[422].first.second, pattern[422].first.first) < smoothedSum(sum, pt, pattern[422].second.second, pattern[422].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[423].first.second, pattern[423].first.first) < smoothedSum(sum, pt, pattern[423].second.second, pattern[423].second.first)) << 0);
        desc[53] =((smoothedSum(sum, pt, pattern[424].first.second, pattern[424].first.first) < smoothedSum(sum, pt, pattern[424].second.second, pattern[424].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[425].first.second, pattern[425].first.first) < smoothedSum(sum, pt, pattern[425].second.second, pattern[425].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[426].first.second, pattern[426].first.first) < smoothedSum(sum, pt, pattern[426].second.second, pattern[426].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[427].first.second, pattern[427].first.first) < smoothedSum(sum, pt, pattern[427].second.second, pattern[427].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[428].first.second, pattern[428].first.first) < smoothedSum(sum, pt, pattern[428].second.second, pattern[428].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[429].first.second, pattern[429].first.first) < smoothedSum(sum, pt, pattern[429].second.second, pattern[429].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[430].first.second, pattern[430].first.first) < smoothedSum(sum, pt, pattern[430].second.second, pattern[430].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[431].first.second, pattern[431].first.first) < smoothedSum(sum, pt, pattern[431].second.second, pattern[431].second.first)) << 0);
        desc[54] =((smoothedSum(sum, pt, pattern[432].first.second, pattern[432].first.first) < smoothedSum(sum, pt, pattern[432].second.second, pattern[432].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[433].first.second, pattern[433].first.first) < smoothedSum(sum, pt, pattern[433].second.second, pattern[433].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[434].first.second, pattern[434].first.first) < smoothedSum(sum, pt, pattern[434].second.second, pattern[434].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[435].first.second, pattern[435].first.first) < smoothedSum(sum, pt, pattern[435].second.second, pattern[435].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[436].first.second, pattern[436].first.first) < smoothedSum(sum, pt, pattern[436].second.second, pattern[436].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[437].first.second, pattern[437].first.first) < smoothedSum(sum, pt, pattern[437].second.second, pattern[437].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[438].first.second, pattern[438].first.first) < smoothedSum(sum, pt, pattern[438].second.second, pattern[438].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[439].first.second, pattern[439].first.first) < smoothedSum(sum, pt, pattern[439].second.second, pattern[439].second.first)) << 0);
        desc[55] =((smoothedSum(sum, pt, pattern[440].first.second, pattern[440].first.first) < smoothedSum(sum, pt, pattern[440].second.second, pattern[440].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[441].first.second, pattern[441].first.first) < smoothedSum(sum, pt, pattern[441].second.second, pattern[441].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[442].first.second, pattern[442].first.first) < smoothedSum(sum, pt, pattern[442].second.second, pattern[442].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[443].first.second, pattern[443].first.first) < smoothedSum(sum, pt, pattern[443].second.second, pattern[443].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[444].first.second, pattern[444].first.first) < smoothedSum(sum, pt, pattern[444].second.second, pattern[444].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[445].first.second, pattern[445].first.first) < smoothedSum(sum, pt, pattern[445].second.second, pattern[445].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[446].first.second, pattern[446].first.first) < smoothedSum(sum, pt, pattern[446].second.second, pattern[446].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[447].first.second, pattern[447].first.first) < smoothedSum(sum, pt, pattern[447].second.second, pattern[447].second.first)) << 0);
        desc[56] =((smoothedSum(sum, pt, pattern[448].first.second, pattern[448].first.first) < smoothedSum(sum, pt, pattern[448].second.second, pattern[448].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[449].first.second, pattern[449].first.first) < smoothedSum(sum, pt, pattern[449].second.second, pattern[449].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[450].first.second, pattern[450].first.first) < smoothedSum(sum, pt, pattern[450].second.second, pattern[450].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[451].first.second, pattern[451].first.first) < smoothedSum(sum, pt, pattern[451].second.second, pattern[451].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[452].first.second, pattern[452].first.first) < smoothedSum(sum, pt, pattern[452].second.second, pattern[452].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[453].first.second, pattern[453].first.first) < smoothedSum(sum, pt, pattern[453].second.second, pattern[453].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[454].first.second, pattern[454].first.first) < smoothedSum(sum, pt, pattern[454].second.second, pattern[454].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[455].first.second, pattern[455].first.first) < smoothedSum(sum, pt, pattern[455].second.second, pattern[455].second.first)) << 0);
        desc[57] =((smoothedSum(sum, pt, pattern[456].first.second, pattern[456].first.first) < smoothedSum(sum, pt, pattern[456].second.second, pattern[456].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[457].first.second, pattern[457].first.first) < smoothedSum(sum, pt, pattern[457].second.second, pattern[457].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[458].first.second, pattern[458].first.first) < smoothedSum(sum, pt, pattern[458].second.second, pattern[458].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[459].first.second, pattern[459].first.first) < smoothedSum(sum, pt, pattern[459].second.second, pattern[459].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[460].first.second, pattern[460].first.first) < smoothedSum(sum, pt, pattern[460].second.second, pattern[460].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[461].first.second, pattern[461].first.first) < smoothedSum(sum, pt, pattern[461].second.second, pattern[461].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[462].first.second, pattern[462].first.first) < smoothedSum(sum, pt, pattern[462].second.second, pattern[462].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[463].first.second, pattern[463].first.first) < smoothedSum(sum, pt, pattern[463].second.second, pattern[463].second.first)) << 0);
        desc[58] =((smoothedSum(sum, pt, pattern[464].first.second, pattern[464].first.first) < smoothedSum(sum, pt, pattern[464].second.second, pattern[464].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[465].first.second, pattern[465].first.first) < smoothedSum(sum, pt, pattern[465].second.second, pattern[465].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[466].first.second, pattern[466].first.first) < smoothedSum(sum, pt, pattern[466].second.second, pattern[466].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[467].first.second, pattern[467].first.first) < smoothedSum(sum, pt, pattern[467].second.second, pattern[467].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[468].first.second, pattern[468].first.first) < smoothedSum(sum, pt, pattern[468].second.second, pattern[468].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[469].first.second, pattern[469].first.first) < smoothedSum(sum, pt, pattern[469].second.second, pattern[469].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[470].first.second, pattern[470].first.first) < smoothedSum(sum, pt, pattern[470].second.second, pattern[470].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[471].first.second, pattern[471].first.first) < smoothedSum(sum, pt, pattern[471].second.second, pattern[471].second.first)) << 0);
        desc[59] =((smoothedSum(sum, pt, pattern[472].first.second, pattern[472].first.first) < smoothedSum(sum, pt, pattern[472].second.second, pattern[472].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[473].first.second, pattern[473].first.first) < smoothedSum(sum, pt, pattern[473].second.second, pattern[473].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[474].first.second, pattern[474].first.first) < smoothedSum(sum, pt, pattern[474].second.second, pattern[474].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[475].first.second, pattern[475].first.first) < smoothedSum(sum, pt, pattern[475].second.second, pattern[475].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[476].first.second, pattern[476].first.first) < smoothedSum(sum, pt, pattern[476].second.second, pattern[476].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[477].first.second, pattern[477].first.first) < smoothedSum(sum, pt, pattern[477].second.second, pattern[477].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[478].first.second, pattern[478].first.first) < smoothedSum(sum, pt, pattern[478].second.second, pattern[478].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[479].first.second, pattern[479].first.first) < smoothedSum(sum, pt, pattern[479].second.second, pattern[479].second.first)) << 0);
        desc[60] =((smoothedSum(sum, pt, pattern[480].first.second, pattern[480].first.first) < smoothedSum(sum, pt, pattern[480].second.second, pattern[480].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[481].first.second, pattern[481].first.first) < smoothedSum(sum, pt, pattern[481].second.second, pattern[481].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[482].first.second, pattern[482].first.first) < smoothedSum(sum, pt, pattern[482].second.second, pattern[482].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[483].first.second, pattern[483].first.first) < smoothedSum(sum, pt, pattern[483].second.second, pattern[483].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[484].first.second, pattern[484].first.first) < smoothedSum(sum, pt, pattern[484].second.second, pattern[484].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[485].first.second, pattern[485].first.first) < smoothedSum(sum, pt, pattern[485].second.second, pattern[485].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[486].first.second, pattern[486].first.first) < smoothedSum(sum, pt, pattern[486].second.second, pattern[486].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[487].first.second, pattern[487].first.first) < smoothedSum(sum, pt, pattern[487].second.second, pattern[487].second.first)) << 0);
        desc[61] =((smoothedSum(sum, pt, pattern[488].first.second, pattern[488].first.first) < smoothedSum(sum, pt, pattern[488].second.second, pattern[488].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[489].first.second, pattern[489].first.first) < smoothedSum(sum, pt, pattern[489].second.second, pattern[489].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[490].first.second, pattern[490].first.first) < smoothedSum(sum, pt, pattern[490].second.second, pattern[490].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[491].first.second, pattern[491].first.first) < smoothedSum(sum, pt, pattern[491].second.second, pattern[491].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[492].first.second, pattern[492].first.first) < smoothedSum(sum, pt, pattern[492].second.second, pattern[492].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[493].first.second, pattern[493].first.first) < smoothedSum(sum, pt, pattern[493].second.second, pattern[493].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[494].first.second, pattern[494].first.first) < smoothedSum(sum, pt, pattern[494].second.second, pattern[494].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[495].first.second, pattern[495].first.first) < smoothedSum(sum, pt, pattern[495].second.second, pattern[495].second.first)) << 0);
        desc[62] =((smoothedSum(sum, pt, pattern[496].first.second, pattern[496].first.first) < smoothedSum(sum, pt, pattern[496].second.second, pattern[496].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[497].first.second, pattern[497].first.first) < smoothedSum(sum, pt, pattern[497].second.second, pattern[497].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[498].first.second, pattern[498].first.first) < smoothedSum(sum, pt, pattern[498].second.second, pattern[498].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[499].first.second, pattern[499].first.first) < smoothedSum(sum, pt, pattern[499].second.second, pattern[499].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[500].first.second, pattern[500].first.first) < smoothedSum(sum, pt, pattern[500].second.second, pattern[500].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[501].first.second, pattern[501].first.first) < smoothedSum(sum, pt, pattern[501].second.second, pattern[501].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[502].first.second, pattern[502].first.first) < smoothedSum(sum, pt, pattern[502].second.second, pattern[502].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[503].first.second, pattern[503].first.first) < smoothedSum(sum, pt, pattern[503].second.second, pattern[503].second.first)) << 0);
        desc[63] =((smoothedSum(sum, pt, pattern[504].first.second, pattern[504].first.first) < smoothedSum(sum, pt, pattern[504].second.second, pattern[504].second.first)) << 7) +
                ((smoothedSum(sum, pt, pattern[505].first.second, pattern[505].first.first) < smoothedSum(sum, pt, pattern[505].second.second, pattern[505].second.first)) << 6) +
                ((smoothedSum(sum, pt, pattern[506].first.second, pattern[506].first.first) < smoothedSum(sum, pt, pattern[506].second.second, pattern[506].second.first)) << 5) +
                ((smoothedSum(sum, pt, pattern[507].first.second, pattern[507].first.first) < smoothedSum(sum, pt, pattern[507].second.second, pattern[507].second.first)) << 4) +
                ((smoothedSum(sum, pt, pattern[508].first.second, pattern[508].first.first) < smoothedSum(sum, pt, pattern[508].second.second, pattern[508].second.first)) << 3) +
                ((smoothedSum(sum, pt, pattern[509].first.second, pattern[509].first.first) < smoothedSum(sum, pt, pattern[509].second.second, pattern[509].second.first)) << 2) +
                ((smoothedSum(sum, pt, pattern[510].first.second, pattern[510].first.first) < smoothedSum(sum, pt, pattern[510].second.second, pattern[510].second.first)) << 1) +
                ((smoothedSum(sum, pt, pattern[511].first.second, pattern[511].first.first) < smoothedSum(sum, pt, pattern[511].second.second, pattern[511].second.first)) << 0);
    }