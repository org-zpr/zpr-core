use std::ops::AddAssign;

/// Simple struct that stores last SIZE samples of some data, overwriting the oldest after that
pub struct SampleRing<Type, const SIZE: usize> {
    pub samples: [Type; SIZE],
    next_sample_idx: usize,
    num_samples: usize,
}

impl<Type: std::marker::Copy + std::cmp::Ord + AddAssign, const SIZE: usize>
    SampleRing<Type, SIZE>
{
    pub fn new(init: Type) -> Self {
        Self {
            samples: [init; SIZE],
            next_sample_idx: 0,
            num_samples: 0,
        }
    }

    /// Add a new sample to the ring
    pub fn add(&mut self, sample: Type) {
        self.samples[self.next_sample_idx] = sample;
        self.next_sample_idx = (self.next_sample_idx + 1) % SIZE;
        self.num_samples = std::cmp::min(SIZE, self.num_samples + 1);
    }

    /// Get the min value from the data collected
    pub fn get_min(&self) -> Type {
        let mut min = self.samples[0];
        if self.num_samples > 1 {
            for sample in &self.samples[1..self.num_samples] {
                min = std::cmp::min(min, *sample);
            }
        }
        min
    }

    /// Get the max value from the data collected
    pub fn get_max(&self) -> Type {
        let mut max = self.samples[0];
        if self.num_samples > 1 {
            for sample in &self.samples[1..self.num_samples] {
                max = std::cmp::max(max, *sample);
            }
        }
        max
    }

    /// Return total and count of data stored so that an average can be calculated
    pub fn get_total_and_count(&self) -> (Type, usize) {
        let mut running_total = self.samples[0];
        if self.num_samples > 1 {
            for sample in &self.samples[1..self.num_samples] {
                running_total.add_assign(*sample);
            }
        }
        (running_total, self.num_samples)
    }
}
