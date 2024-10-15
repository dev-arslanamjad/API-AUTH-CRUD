<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\Post;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class PostController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $data['posts'] = Post::all();
        return response()->json([
            'data' => $data,
            'message' => 'Post retrieved successfully',
            'status' => 200
        ], 200);
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'title' => 'required',
            'description' => 'required',
            'image' => 'required|image|mimes:jpeg,png,jpg,gif|max:4096',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Posts Adding failed',
                'errors' => $validator->errors()->all(),
            ], 422);
        }
        $validatedData = $validator->validated();
        if ($request->hasFile('image')) {
            $image = $request->file('image');
            $imageName = time() . '.' . $image->getClientOriginalExtension();
            $image->move(public_path() . '/uploads', $imageName);
            $validatedData['image'] = $imageName;
        }
        $post = Post::create(([
            'title' => $request->input('title'),
            'description' => $request->input('description'),
            'image' => $validatedData['image'],
        ]));

        return response()->json([
            'status' => 'success',
            'message' => 'Post created successfully',
            'user' => $post,
        ], 200);
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id)
    {
        $data['post'] = Post::select(
            'id',
            'title',
            'description',
            'image',
        )->where(['id' => $id])->get();

        return response()->json([
            'status' => 'success',
            'message' => 'Your Single Post is here',
            'user' => $data,
        ], 200);
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        $validator = Validator::make($request->all(), [
            'title' => 'required',
            'description' => 'required',
            'image' => 'required|image|mimes:jpeg,png,jpg,gif|max:4096',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Posts Adding failed',
                'errors' => $validator->errors()->all(),
            ], 422);
        }
        $validatedData = $validator->validated();
        if ($request->hasFile('image')) {

            $post = Post::select('id', 'image')->where(['id' => $id])->first(); // Use first() instead of get()

            $path = public_path() . '/uploads';
            $old_file = $path . '/' . $post->image; // Access the image attribute correctly.
            if (file_exists($old_file)) {
                unlink($old_file);
            }


            $image = $request->file('image');
            $imageName = time() . '.' . $image->getClientOriginalExtension();
            $image->move(public_path() . '/uploads', $imageName);
            $validatedData['image'] = $imageName;
        }
        $post = Post::where(['id' => $id])->update(([
            'title' => $request->input('title'),
            'description' => $request->input('description'),
            'image' => $validatedData['image'],
        ]));
        $postdata = Post::where(['id' => $id])->first();
        return response()->json([
            'status' => 'success',
            'message' => 'Post Uptaed successfully',
            'post' => $postdata,
        ], 200);
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)

    {
        $post = Post::select('image')->where('id', $id)->first(); // Use first() to get a single post.
        $filePath = public_path() . '/uploads/' . $post->image; // Correctly access the image attribute.
        if (file_exists($filePath)) {
            unlink($filePath);
        }

        Post::where('id', $id)->delete(); // Now delete the post after removing the file.




        return response()->json([
            'status' => 'success',
            'message' => 'Post has been Removed ',
        ], 200);
    }
}
