<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class CategorySeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        DB::table('categories')->insert([
            [
                'name' => "Startup",
                'slug' => "startup"
            ],
            [
                'name' => "Life",
                'slug' => "life"
            ],
            [
                'name' => "Life Lessones",
                'slug' => "life-lessons"
            ],
            [
                'name' => "Politics",
                'slug' => "politics"
            ],
            [
                'name' => "Travel",
                'slug' => "travel"
            ],
            [
                'name' => "Poetry",
                'slug' => "poetry"
            ],
            [
                'name' => "Entrepreneurship",
                'slug' => "entrepreneurship"
            ],
            [
                'name' => "Education",
                'slug' => "education"
            ],
            [
                'name' => "Health",
                'slug' => "health"
            ],
            [
                'name' => "Love",
                'slug' => "love"
            ],
            [
                'name' => "Design",
                'slug' => "design"
            ],
            [
                'name' => "Technology",
                'slug' => "technology"
            ],
        ]);
    }
}
