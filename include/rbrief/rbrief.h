#ifndef RBRIEF_DESCRIPTOR_BRIEF_H
#define RBRIEF_DESCRIPTOR_BRIEF_H

#include <opencv2/features2d/features2d.hpp>
#include <opencv2/imgproc/imgproc.hpp>

#include <utility>

namespace cv
{

class CV_EXPORTS RBriefDescriptorExtractor : public DescriptorExtractor {

	public:
		RBriefDescriptorExtractor(int bytes = 32);

		virtual void computeImpl(const Mat& image, std::vector<KeyPoint>& keypoints, Mat& descriptors) const;
		virtual void compute(const Mat& image, std::vector<KeyPoint>& keypoints, Mat& descriptors) const
		{
			computeImpl(image,keypoints,descriptors);
		}

		virtual int descriptorSize() const
		{
			return bytes_;
		}
		virtual int descriptorType() const
		{
			return CV_8UC1;
		}

		bool setRotationCase(double rotation);
		void freezeRotationCase();

protected:
		static const int PATCH_SIZE = 48;
		static const int KERNEL_SIZE = 9;

		int bytes_;
		std::vector< std::pair< std::pair< int, int >, std::pair< int, int > > > pattern;
		std::vector< std::pair< std::pair< int, int >, std::pair< int, int > > > patternRot;

		typedef void(*PixelTestFn)(const Mat&, const std::vector<KeyPoint>&, Mat&, const std::vector< std::pair< std::pair<int,int>, std::pair<int,int> > > &pattern);
		PixelTestFn test_fn_;

		static int32_t smoothedSum(const Mat& sum, const KeyPoint& pt, int y, int x);

		static void pixelTests4(const Mat& sum, const std::vector<KeyPoint>& keypoints, Mat& descriptors, const std::vector< std::pair< std::pair<int,int>, std::pair<int,int> > > &pattern);
		static void pixelTests16(const Mat& sum, const std::vector<KeyPoint>& keypoints, Mat& descriptors, const std::vector< std::pair< std::pair<int,int>, std::pair<int,int> > > &pattern);
		static void pixelTests32(const Mat& sum, const std::vector<KeyPoint>& keypoints, Mat& descriptors, const std::vector< std::pair< std::pair<int,int>, std::pair<int,int> > > &pattern);
		static void pixelTests64(const Mat& sum, const std::vector<KeyPoint>& keypoints, Mat& descriptors, const std::vector< std::pair< std::pair<int,int>, std::pair<int,int> > > &pattern);

};

inline int32_t RBriefDescriptorExtractor::smoothedSum(const Mat& sum, const KeyPoint& pt, int y, int x)
{
	/// @todo Possibly could be sped up even further by making this a functor and precalculating offsets to corners
	/*
	int tl_offset = -sum.step * HALF_KERNEL - HALF_KERNEL * sizeof(int32_t);
	int tr_offset = -sum.step * HALF_KERNEL + (HALF_KERNEL + 1) * sizeof(int32_t);
	int bl_offset = sum.step * (HALF_KERNEL + 1) - HALF_KERNEL * sizeof(int32_t);
	int br_offset = sum.step * (HALF_KERNEL + 1) + (HALF_KERNEL + 1) * sizeof(int32_t);
	*/

	static const int HALF_KERNEL = KERNEL_SIZE / 2;

	int img_y = (int)(pt.pt.y + 0.5) + y;
	int img_x = (int)(pt.pt.x + 0.5) + x;
	return sum.at<int32_t> (img_y + HALF_KERNEL + 1, img_x + HALF_KERNEL + 1)
			- sum.at<int32_t> (img_y + HALF_KERNEL + 1, img_x - HALF_KERNEL)
			- sum.at<int32_t> (img_y - HALF_KERNEL, img_x + HALF_KERNEL + 1)
			+ sum.at<int32_t> (img_y - HALF_KERNEL, img_x - HALF_KERNEL);
}

} // namespace cv

#endif
